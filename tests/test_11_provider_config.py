import json
import os
from urllib.parse import parse_qs, urlparse

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from oic.utils.authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.endpoint_context import EndpointContext

from fedservice import Collector, FederationEntity
from fedservice.entity_statement.collect import Issuer
from fedservice.op.service import ProviderConfiguration
from .utils import build_path

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

BASE_URL = 'https://127.0.0.1:6000'
ROOT_DIR = os.path.join(BASE_PATH, 'fedA')
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
RECEIVER = 'https://example.org/op'


class DummyCollector(Collector):
    def __init__(self, httpd=None, trusted_roots=None, root_dir='.',
                 base_url=''):
        Collector.__init__(self, httpd, trusted_roots=trusted_roots)
        self.root_dir = root_dir
        self.base_url = base_url

    def collect_entity_statements(self, response):
        _jwt = factory(response)
        if _jwt:
            entity_statement = _jwt.jwt.payload()
        else:
            return None

        node = Issuer(response)

        for authority, roots in entity_statement['authority_hints'].items():
            node.superior.append(
                build_path(self.root_dir, self.base_url, authority,
                           sub=entity_statement['iss']))

        return node


class MockResponse():
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class Publisher(object):
    def __init__(self, directory):
        self.dir = directory

    def __call__(self, method, url, **kwargs):
        p = urlparse(url)
        _qs = parse_qs(p.query)
        pt = urlparse(_qs['sub'][0])
        _jws = open(os.path.join(self.dir, p.netloc, pt.netloc)).read().strip()

        return MockResponse(200, '["{}"]'.format(_jws),
                            headers={'content-type': "application/jws"})


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {},
            "authentication": [{
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'NoAuthn',
                'kwargs': {'user': 'diana'}
            }],
            'template_dir': 'template'
        }
        endpoint_context = EndpointContext(conf, keyjar=build_keyjar(KEYSPEC))
        self.endpoint = ProviderConfiguration(endpoint_context)

        # === Federation stuff =======
        trusted_roots = json.loads(
            open(os.path.join(BASE_PATH, 'trust_roots_wt.json')).read())
        key_jar = build_keyjar(KEYSPEC, owner='abcdefghi')

        federation_entity = FederationEntity(
            'abcdefghi', key_jar=key_jar, trusted_roots=trusted_roots,
            authority_hints={},
            httpd=Publisher(os.path.join(BASE_PATH, 'data')))

        federation_entity.collector = DummyCollector(
            httpd=Publisher(os.path.join(BASE_PATH, 'data')),
            trusted_roots=trusted_roots,
            root_dir=ROOT_DIR, base_url=BASE_URL)

        self.fedent = federation_entity
        self.endpoint.endpoint_context.federation_entity = federation_entity

    def test_do_response(self):
        args = self.endpoint.process_request()
        info = self.endpoint.do_response(**args)
        _jwt = factory(info['response'])
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'kid', 'iat',
                                       'metadata', 'iss'}
        assert set(payload['metadata'].keys()) == {
            'response_types_supported', 'claims_supported',
            'claims_parameter_supported', 'grant_types_supported',
            'token_endpoint_auth_signing_alg_values_supported',
            'request_object_encryption_enc_values_supported',
            'request_object_signing_alg_values_supported',
            'request_uri_parameter_supported',
            'userinfo_encryption_enc_values_supported',
            'subject_types_supported',
            'request_parameter_supported',
            'id_token_encryption_alg_values_supported',
            'require_request_uri_registration', 'acr_values_supported',
            'claim_types_supported', 'version',
            'userinfo_encryption_alg_values_supported',
            'userinfo_signing_alg_values_supported',
            'id_token_signing_alg_values_supported', 'issuer',
            'request_object_encryption_alg_values_supported',
            'token_endpoint_auth_methods_supported',
            'id_token_encryption_enc_values_supported',
            'response_modes_supported', 'scopes_supported'}
