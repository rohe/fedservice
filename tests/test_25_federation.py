import json
import os
from urllib.parse import parse_qs

from oidcop.configure import Configuration as OPConfiguration
from oidcop.configure import add_base_path
from oidcrp.configure import Configuration
import pytest
import responses

from fedservice.op import init_oidc_op_endpoints
from fedservice.rp import init_oidc_rp_handler
from fedservice.utils import compact
from tests.utils import DummyCollector
from tests.utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()
ANCHOR = {'https://feide.no': json.loads(jwks)}


def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)


def test_init_rp():
    config = Configuration.create_from_config_file(full_path('conf_foodle.uninett.no.yaml'),
                                                   base_path=BASE_PATH)
    rph = init_oidc_rp_handler(config, BASE_PATH)
    rp = rph.init_client('ntnu')
    assert rp


class TestFed(object):
    @pytest.fixture(autouse=True)
    def create_op_enpoint_context(self):
        op_conf = OPConfiguration.create_from_config_file(full_path('conf_op.ntnu.no.yaml'),
                                                          base_path=BASE_PATH)

        add_base_path(op_conf.op["server_info"]["federation"],
                      {
                          "keys": ['private_path', 'public_path'],
                          "": ["authority_hints", "trusted_roots"]
                      },
                      BASE_PATH)

        _endpoint_context = init_oidc_op_endpoints(op_conf, BASE_PATH)
        _endpoint_context.federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.provider_endpoint = _endpoint_context.endpoint['provider_config']
        self.registration_endpoint = _endpoint_context.endpoint["registration"]
        self.authorization_endpoint = _endpoint_context.endpoint["authorization"]

    def test_explicit_registration(self):
        config = Configuration.create_from_config_file(full_path('conf_foodle.uninett.no.yaml'),
                                                       base_path=BASE_PATH)

        rph = init_oidc_rp_handler(config, BASE_PATH)

        rp = rph.init_client('ntnu')
        rp.service_context.federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        _service = rp.service['provider_info']

        args = self.provider_endpoint.process_request()
        info = self.provider_endpoint.do_response(**args)

        _resp = _service.parse_response(info["response"])

        with responses.RequestsMock() as rsps:
            _jwks = open(
                os.path.join(BASE_PATH, 'base_data', 'ntnu.no', 'op.ntnu.no', 'jwks.json')).read()
            rsps.add("GET", "https://op.ntnu.no/static/jwks.json", body=_jwks,
                     adding_headers={"Content-Type": "application/json"}, status=200)
            _service.update_service_context(_resp)

        # Do the client registration request
        # First let the client construct the client registration request
        _service = rp.service['registration']
        _request_args = _service.get_request_parameters()

        # send it to the provider
        args = self.registration_endpoint.process_request(_request_args["body"])
        response_args = self.provider_endpoint.do_response(**args)

        # Let the client deal with the response from the provider

        _resp = _service.parse_response(response_args["response"], request=_request_args["body"])
        _service.update_service_context(_resp)

        # and we're done
        reg_resp = _service.service_context.get("registration_response")
        assert reg_resp["token_endpoint_auth_method"] == "private_key_jwt"

    def test_automatic_registration(self):
        config = Configuration.create_from_config_file(full_path('conf_foodle.uninett.no.yaml'),
                                                       base_path=BASE_PATH)

        rph = init_oidc_rp_handler(config, BASE_PATH)

        rp = rph.init_client('ntnu')
        rp.service_context.federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        _service = rp.service['provider_info']

        # don't need to parse the request since there is none
        args = self.provider_endpoint.process_request()
        info = self.provider_endpoint.do_response(**args)

        _resp = _service.parse_response(info["response"])

        with responses.RequestsMock() as rsps:
            _jwks = open(
                os.path.join(BASE_PATH, 'base_data', 'ntnu.no', 'op.ntnu.no', 'jwks.json')).read()
            rsps.add("GET", "https://op.ntnu.no/static/jwks.json", body=_jwks,
                     adding_headers={"Content-Type": "application/json"}, status=200)
            _service.update_service_context(_resp)

        # Do the client authorization request
        # First let the client construct the authorization request
        _service = rp.service['authorization']
        _request_args = _service.get_request_parameters()

        # send it to the provider
        _req_args = parse_qs(_request_args['url'].split('?')[1])
        with responses.RequestsMock() as rsps:
            _jwks = open(os.path.join(BASE_PATH, 'static/jwks_auto.json')).read()
            _url = 'https://foodle.uninett.no/jwks.json'
            rsps.add("GET", _url, body=_jwks, adding_headers={"Content-Type": "application/json"},
                     status=200)
            _req_args = self.authorization_endpoint.parse_request(compact(_req_args))

        # need to register a user session info
        args = self.authorization_endpoint.process_request(_req_args)
        response_args = self.authorization_endpoint.do_response(**args)

        # Let the client deal with the response from the provider

        _resp = _service.parse_response(response_args["response"], request=compact(_req_args))
        _service.update_service_context(_resp)

        # and we're done
        assert 'trust_anchor_id' in _resp
