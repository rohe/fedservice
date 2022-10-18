import os

from cryptojwt.jws.jws import factory
from idpyoidc.server.user_authn.authn_context import UNSPECIFIED
from idpyoidc.server.user_authn.user import NoAuthn
import pytest

from fedservice.entity.server.fetch import Fetch
from fedservice.fetch_entity_statement.fs2 import FSPublisher
from fedservice.fetch_entity_statement.fs2 import read_info
from fedservice.op.provider_config import ProviderConfiguration
from tests.utils import DummyCollector

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
            "claims_interface": {"class": "idpyoidc.server.session.claims.ClaimsInterface", "kwargs": {}},
            'keys': {
                'key_defs': KEYSPEC,
                "private_path": "own/jwks.json",
                "uri_path": "static/jwks.json"
            },
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                }
            },
            "authentication": {
                "anon": {
                    'acr': UNSPECIFIED,
                    "class": NoAuthn,
                    "kwargs": {"user": "diana"}
                }
            },
            'template_dir': 'template',
            "federation": {
                "entity_id": ENTITY_ID,
                'keys': {'key_defs': KEYSPEC},
                "endpoint": {
                    "fetch": {
                        "path": "fetch",
                        "class": Fetch,
                        "kwargs": {"client_authn_method": None},
                    }
                },
                "trusted_roots": ANCHOR,
                "authority_hints": ['https://feide.no'],
                "entity_type": 'openid_relying_party',
                "opponent_entity_type": 'openid_provider'
            }
        }
        server = FederationServer(conf)
        self.endpoint = server.server_get('endpoint', 'provider_config')

        server.endpoint_context.federation_entity.collector = DummyCollector(
            httpc=FSPublisher(os.path.join(BASE_PATH, 'data')),
            trust_anchors=ANCHOR,
            root_dir=ROOT_DIR)

    def test_do_response(self):
        args = self.endpoint.process_request()
        info = self.endpoint.do_response(**args)
        _jwt = factory(info['response'])
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'iat',
                                       'metadata', 'iss', 'authority_hints'}
        assert set(payload['metadata'].keys()) == {'openid_relying_party'}
        for i in payload['metadata']['openid_relying_party'].keys():
            assert i in (
                'acr_values_supported', 'claims_parameter_supported',
                'claims_supported', 'grant_types_supported', 'scopes_supported',
                'id_token_encryption_alg_values_supported',
                'id_token_encryption_enc_values_supported',
                'id_token_signing_alg_values_supported', 'issuer', 'jwks_uri',
                'request_parameter_supported', 'request_uri_parameter_supported',
                'require_request_uri_registration', 'token_endpoint_auth_methods_supported',
                'version')
