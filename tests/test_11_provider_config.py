import os

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn

from fedservice import FederationEntity
from fedservice.metadata_api.fs2 import read_info
from fedservice.op.provider_config import ProviderConfiguration
from tests.utils import DummyCollector
from tests.utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ENTITY_ID = 'https://op.ntnu.no'

ANCHOR = {'https://feide.no': read_info(os.path.join(ROOT_DIR, 'feide.no'), "feide.no", "jwks")}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ENTITY_ID,
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            'keys': {
                'key_defs': KEYSPEC,
                "private_path": "own/jwks.json",
                "uri_path": "static/jwks.json"
            },
            "endpoint": {},
            "authentication": {
                "anon": {
                    'acr': UNSPECIFIED,
                    "class": NoAuthn,
                    "kwargs": {"user": "diana"}
                }
            },
            'template_dir': 'template'
        }
        endpoint_context = EndpointContext(conf)
        self.endpoint = ProviderConfiguration(endpoint_context)

        # === Federation stuff =======
        fe_conf = {
            'keys': {'key_defs': KEYSPEC}
        }

        federation_entity = FederationEntity(
            ENTITY_ID, trusted_roots=ANCHOR,
            authority_hints={'https://ntnu.no': ['https://feide.no']},
            httpd=Publisher(ROOT_DIR), config=fe_conf,
            entity_type='openid_relying_party', opponent_entity_type='openid_provider')

        federation_entity.collector = DummyCollector(
            httpd=Publisher(os.path.join(BASE_PATH, 'data')),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.fedent = federation_entity
        self.endpoint.endpoint_context.federation_entity = federation_entity

    def test_do_response(self):
        args = self.endpoint.process_request()
        info = self.endpoint.do_response(**args)
        _jwt = factory(info['response'])
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'iat',
                                       'metadata', 'iss', 'authority_hints'}
        assert set(payload['metadata'].keys()) == {'openid_relying_party'}
        assert set(payload['metadata']['openid_relying_party'].keys()) == {
            'acr_values_supported', 'claims_parameter_supported',
            'claims_supported', 'grant_types_supported', 'scopes_supported',
            'id_token_encryption_alg_values_supported', 'id_token_encryption_enc_values_supported',
            'id_token_signing_alg_values_supported', 'issuer', 'jwks_uri',
            'request_parameter_supported', 'request_uri_parameter_supported',
            'require_request_uri_registration', 'token_endpoint_auth_methods_supported', 'version'}
