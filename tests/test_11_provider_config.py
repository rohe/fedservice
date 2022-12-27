import os

import pytest
from cryptojwt.jws.jws import factory

from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.entity import FederationEntity
from fedservice.op import ServerEntity
from fedservice.op.authorization import Authorization
from fedservice.op.provider_config import ProviderConfiguration
from fedservice.trust_mark_issuer import TrustMarkIssuer
from tests import CRYPT_CONFIG
from tests import RESPONSE_TYPES_SUPPORTED
from tests import SESSION_PARAMS
from tests.build_entity import FederationEntityBuilder

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

OP_ID = 'https://op.example.com'
TA_ID = 'https://ta.example.com'

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
del TA_ENDPOINTS["resolve"]
del TA_ENDPOINTS['status']


class TestEndpoint(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #          TA
        #          |
        #          OP

        # TRUST ANCHOR

        TA = FederationEntityBuilder(
            TA_ID,
            metadata={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_conf={"key_defs": KEYSPEC}
        )
        TA.add_endpoints(None, **TA_ENDPOINTS)

        self.ta = FederationEntity(**TA.conf)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        OP_FE = FederationEntityBuilder(
            OP_ID,
            metadata={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            authority_hints=[TA_ID]
        )
        OP_FE.add_services()
        OP_FE.add_functions()
        OP_FE.add_endpoints()
        OP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR
        OP_FE.conf['server']['kwargs']['endpoint']['status']['kwargs'][
            'trust_mark_issuer'] = {
            'class': TrustMarkIssuer,
            'kwargs': {
                'key_conf': {"key_defs": KEYSPEC}
            }
        }

        OP_CONFIG = {
            'entity_id': OP_ID,
            'key_conf': {"key_defs": KEYSPEC},
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': OP_FE.conf
            },
            "openid_provider": {
                'class': ServerEntity,
                'kwargs': {
                    'config': {
                        "issuer": "https://example.com/",
                        "httpc_params": {"verify": False, "timeout": 1},
                        "capabilities": {
                            "subject_types_supported": ["public", "pairwise", "ephemeral"],
                            "grant_types_supported": [
                                "authorization_code",
                                "implicit",
                                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                "refresh_token",
                            ],
                        },
                        "token_handler_args": {
                            "jwks_def": {
                                "private_path": "private/token_jwks.json",
                                "read_only": False,
                                "key_defs": [
                                    {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
                            },
                            "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                            "token": {
                                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                                "kwargs": {
                                    "lifetime": 3600,
                                    "add_claims_by_scope": True,
                                    "aud": ["https://example.org/appl"],
                                },
                            },
                            "refresh": {
                                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                                "kwargs": {
                                    "lifetime": 3600,
                                    "aud": ["https://example.org/appl"],
                                },
                            },
                            "id_token": {
                                "class": "idpyoidc.server.token.id_token.IDToken",
                                "kwargs": {
                                    "base_claims": {
                                        "email": {"essential": True},
                                        "email_verified": {"essential": True},
                                    }
                                },
                            },
                        },
                        "keys": {"key_defs": KEYSPEC, "uri_path": "static/jwks.json"},
                        "endpoint": {
                            "provider_config": {
                                "path": ".well-known/openid-configuration",
                                "class": ProviderConfiguration,
                                "kwargs": {},
                            },
                            "authorization": {
                                "path": "authorization",
                                "class": Authorization,
                                "kwargs": {
                                    "response_types_supported": [" ".join(x) for x in
                                                                 RESPONSE_TYPES_SUPPORTED],
                                    "response_modes_supported": ["query", "fragment", "form_post"],
                                    "claim_types_supported": [
                                        "normal",
                                        "aggregated",
                                        "distributed",
                                    ],
                                    "claims_parameter_supported": True,
                                    "request_parameter_supported": True,
                                    "request_uri_parameter_supported": True,
                                },
                            },
                        },
                        "template_dir": "template",
                        "session_params": SESSION_PARAMS,
                    }
                }
            }
        }

        self.op = FederationCombo(OP_CONFIG)

        self.endpoint = self.op['openid_provider'].get_endpoint('provider_config')
        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]

        }

    def test_do_response(self):
        args = self.endpoint.process_request()
        info = self.endpoint.do_response(**args)
        _jwt = factory(info['response'])
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'iat',
                                       'metadata', 'iss', 'authority_hints'}
        assert set(payload['metadata'].keys()) == {'openid_provider'}
        assert set(payload['metadata']['openid_provider'].keys()) == {
            'authorization_endpoint',
            'claims_parameter_supported',
            'client_registration_types_supported',
            'grant_types_supported',
            'id_token_signing_alg_values_supported',
            'issuer',
            'jwks_uri',
            'request_authentication_methods_supported',
            'request_authentication_signing_alg_values_supported',
            'request_object_signing_alg_values_supported',
            'request_parameter_supported',
            'request_uri_parameter_supported',
            'require_request_uri_registration',
            'response_modes_supported',
            'response_types_supported',
            'scopes_supported',
            'subject_types_supported',
            'token_endpoint_auth_methods_supported',
            'version'}
