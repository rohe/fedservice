import os

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from oidcendpoint import user_authn
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn

from fedservice import FederationEntity
from fedservice.metadata_api.fs import read_info
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
            "endpoint": {},
            "jwks": {
                "private_path": "own/jwks.json",
                "uri_path": "static/jwks.json"
            },
            "authentication": {
                "anon": {
                    'acr': UNSPECIFIED,
                    "class": NoAuthn,
                    "kwargs":{"user": "diana"}
                }
            },
            'template_dir': 'template'
        }
        endpoint_context = EndpointContext(conf, keyjar=build_keyjar(KEYSPEC))
        self.endpoint = ProviderConfiguration(endpoint_context)

        # === Federation stuff =======
        key_jar = build_keyjar(KEYSPEC, owner=ENTITY_ID)

        federation_entity = FederationEntity(
            ENTITY_ID, key_jar=key_jar, trusted_roots=ANCHOR,
            authority_hints={'https://ntnu.no': ['https://feide.no']},
            httpd=Publisher(ROOT_DIR),
            entity_type='openid_client', opponent_entity_type='openid_provider')

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
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'kid', 'iat',
                                       'metadata', 'iss', 'authority_hints'}
        assert set(payload['metadata'].keys()) == {'openid_client'}
        assert set(payload['metadata']['openid_client'].keys()) == {
            'response_types_supported', 'claims_supported',
            'claims_parameter_supported', 'grant_types_supported',
            'token_endpoint_auth_signing_alg_values_supported',
            'request_object_encryption_enc_values_supported',
            'request_object_signing_alg_values_supported',
            'request_uri_parameter_supported',
            'userinfo_encryption_enc_values_supported',
            'subject_types_supported', "jwks_uri",
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
