import json
import os
import sys
from urllib.parse import parse_qs

from oidcmsg.configure import Configuration
from oidcmsg.configure import create_from_config_file
from oidcop.utils import lower_or_upper
import pytest
import responses

from fedservice.configure import DEFAULT_FED_FILE_ATTRIBUTE_NAMES
from fedservice.configure import FedOpConfiguration
from fedservice.configure import FedRPConfiguration
from fedservice.rp import init_oidc_rp_handler
from fedservice.server import Server
from fedservice.utils import compact
from tests.utils import DummyCollector
from tests.utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

dir_path = os.path.dirname(os.path.realpath(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()
ANCHOR = {'https://feide.no': json.loads(jwks)}


def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)


def test_init_rp():
    config = create_from_config_file(FedRPConfiguration,
                                     entity_conf=[{"class": FedRPConfiguration, "attr": "rp"}],
                                     filename=full_path('conf_foodle.uninett.no_auto.json'),
                                     base_path=BASE_PATH)
    rph = init_oidc_rp_handler(config, BASE_PATH)
    rp = rph.init_client('ntnu')
    assert rp


class TestFed(object):
    @pytest.fixture(autouse=True)
    def create_op_enpoint_context(self):
        cwd = os.getcwd()
        if cwd.endswith('tests'):
            sys.path.append(".")
        else:  # assume it's run from the package root dir
            sys.path.append("tests")
        import conf_op_umu_se

        _conf = conf_op_umu_se.CONF.copy()

        configuration = FedOpConfiguration(conf=_conf, base_path=BASE_PATH, domain="127.0.0.1",
                                           port=443)
        server = Server(configuration)

        # _endpoint_context = init_oidc_op_endpoints(op_conf, BASE_PATH)
        _endpoint_context = server.get_endpoint_context()
        _endpoint_context.federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.provider_endpoint = server.server_get("endpoint", 'provider_config')
        self.registration_endpoint = server.server_get("endpoint", "registration")
        self.authorization_endpoint = server.server_get("endpoint", "authorization")

    def test_explicit_registration(self):
        config = create_from_config_file(Configuration,
                                         entity_conf=[{"class": FedRPConfiguration, "attr": "rp"}],
                                         filename=full_path('conf_foodle.uninett.no_expl.json'),
                                         file_attributes=DEFAULT_FED_FILE_ATTRIBUTE_NAMES,
                                         base_path=BASE_PATH)

        config.rp.federation.web_cert_path = "{}/{}".format(dir_path,
                                                            lower_or_upper(config.web_conf,
                                                                           "server_cert"))

        rph = init_oidc_rp_handler(config.rp, BASE_PATH)

        # MUST be an unknown entity
        rp = rph.init_client('https://op.umu.se')
        rp.client_get("service_context").federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        _service = rp.client_get("service", 'provider_info')

        args = self.provider_endpoint.process_request()
        info = self.provider_endpoint.do_response(**args)

        _resp = _service.parse_response(info["response"])

        with responses.RequestsMock() as rsps:
            _jwks = open(
                os.path.join(BASE_PATH, 'base_data', 'umu.se', 'op.umu.se', 'jwks.json')).read()
            rsps.add("GET", 'https://op.umu.se/static/umu_se_jwks.json', body=_jwks,
                     adding_headers={"Content-Type": "application/json"}, status=200)
            _service.update_service_context(_resp)

        # Do the client registration request
        # First let the client construct the client registration request
        _service = rp.client_get("service", 'registration')
        #_request_args = _service.get_request_parameters(behaviour_args={'add_callbacks':{'add_hash':False}})
        _request_args = _service.get_request_parameters()

        # On the provider side
        args = self.registration_endpoint.process_request(_request_args["body"])
        response_args = self.provider_endpoint.do_response(**args)

        # Let the client deal with the response from the provider

        _resp = _service.parse_response(response_args["response"], request=_request_args["body"])
        _service.update_service_context(_resp)

        # and we're done
        reg_resp = _service.client_get("service_context").get("registration_response")
        assert reg_resp["token_endpoint_auth_method"] == "private_key_jwt"

    def test_automatic_registration(self):
        config = create_from_config_file(Configuration,
                                         entity_conf=[{"class": FedRPConfiguration, "attr": "rp"}],
                                         filename=full_path('conf_foodle.uninett.no_auto.json'),
                                         file_attributes=DEFAULT_FED_FILE_ATTRIBUTE_NAMES,
                                         base_path=BASE_PATH)

        rph = init_oidc_rp_handler(config.rp, BASE_PATH)

        rp = rph.init_client('https://op.umu.se')
        rp.client_get("service_context").federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        _service = rp.client_get("service", 'provider_info')

        # don't need to parse the request since there is none
        args = self.provider_endpoint.process_request()
        info = self.provider_endpoint.do_response(**args)

        _resp = _service.parse_response(info["response"])

        with responses.RequestsMock() as rsps:
            _jwks = open(
                os.path.join(BASE_PATH, 'base_data', 'umu.se', 'op.umu.se', 'jwks.json')).read()
            rsps.add("GET", 'https://op.umu.se/static/umu_se_jwks.json', body=_jwks,
                     adding_headers={"Content-Type": "application/json"}, status=200)
            _service.update_service_context(_resp)

        # Do the client authorization request
        # First let the client construct the authorization request
        _service = rp.client_get("service", 'authorization')
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
