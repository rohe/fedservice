import os

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo
import pytest
import responses

from fedservice.appserver.oidc.authorization import Authorization
from fedservice.appserver.oidc.registration import Registration
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from . import CRYPT_CONFIG
from . import RESPONSE_TYPES_SUPPORTED
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]}
]

TA_ID = "https://ta.example.org"
OC_ID = "https://rp.example.org"
AS_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

OIDC_SERVICE = DEFAULT_OIDC_SERVICES.copy()
OIDC_SERVICE.update(DEFAULT_OIDC_FED_SERVICES)

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [OC_ID, AS_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    OC_ID: {
        "oauth_client": {
            'class': "fedservice.appclient.ClientEntity",
            'kwargs': {
                # OIDC core keys
                "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                'config': {
                    'base_url': OC_ID,
                    'client_id': OC_ID,
                    'client_secret': 'a longesh password',
                    'client_type': 'oidc',
                    'redirect_uris': ['https://rp.example.com/cli/authz_cb'],
                    "preference": {
                        "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                        "id_token_signed_response_alg": "ES256",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "token_endpoint_auth_signing_alg": "ES256",
                        "client_registration_types": ["automatic"],
                        "request_parameter_supported": True
                    },
                    "authorization_request_endpoints": [
                        'authorization_endpoint', 'pushed_authorization_request_endpoint'
                    ],
                },
                "services": OIDC_SERVICE
            }
        }
    },
    AS_ID: {
        "oauth_authorization_server": {
            'class': 'fedservice.appserver.ServerEntity',
            'kwargs': {
                'config': {
                    "issuer": AS_ID,
                    "httpc_params": {"verify": False, "timeout": 1},
                    "preference": {
                        'request_authentication_methods_supported': {
                            "authorization_endpoint": [
                                "request_object"
                            ],
                            "pushed_authorization_request_endpoint": [
                                "private_key_jwt"
                            ]
                        },
                        "subject_types_supported": ["public", "pairwise", "ephemeral"],
                        "grant_types_supported": [
                            "authorization_code",
                            "implicit",
                            "urn:ietf:params:oauth:grant-type:jwt-bearer",
                            "refresh_token",
                        ]
                    },
                    "token_handler_args": {
                        "jwks_def": {
                            "private_path": "private/token_jwks.json",
                            "read_only": False,
                            "key_defs": [
                                {"type": "oct", "bytes": "24", "use": ["enc"],
                                 "kid": "code"}],
                        },
                        "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                        "token": {
                            "class": "idpyoidc.server.token.jwt_token.JWTToken",
                            "kwargs": {
                                "lifetime": 3600,
                                "add_claims_by_scope": True,
                            },
                        },
                        "id_token": {
                            "class": "idpyoidc.server.token.id_token.IDToken",
                            "kwargs": {
                                "base_claims": {
                                    "email": {"essential": True},
                                    "email_verified": {"essential": True},
                                }
                            }
                        }
                    },
                    "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "endpoint": {
                        "registration": {
                            "path": "registration",
                            "class": Registration,
                            "kwargs": {"client_auth_method": None},
                        },
                        "authorization": {
                            "path": "authorization",
                            "class": Authorization,
                            "kwargs": {
                                "response_types_supported": [" ".join(x) for x in
                                                             RESPONSE_TYPES_SUPPORTED],
                                "response_modes_supported": ["query", "fragment",
                                                             "form_post"],
                                "claim_types_supported": [
                                    "normal",
                                    "aggregated",
                                    "distributed",
                                ],
                                "claims_parameter_supported": True,
                                "request_parameter_supported": True,
                                "request_uri_parameter_supported": True,
                                "client_registration_types_supported": ['automatic',
                                                                        'explicit']
                            },
                        },
                        "token": {
                            "path": "token",
                            "class": Token,
                            "kwargs": {
                                "client_authn_method": [
                                    "client_secret_post",
                                    "client_secret_basic",
                                    "client_secret_jwt",
                                    "private_key_jwt",
                                ]
                            },
                        },
                        "userinfo": {
                            "path": "userinfo",
                            "class": UserInfo,
                            "kwargs": {}
                        },
                    },
                    "template_dir": "template",
                    "session_params": SESSION_PARAMS,
                }
            },
            'key_conf': {"key_defs": DEFAULT_KEY_DEFS},
            "services": OIDC_SERVICE
        }
    },
    IM_ID: {
        "entity_type": "federation_entity",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
        }
    }
}


class TestAutomatic(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.oc = federation[OC_ID]
        self.oas = federation[AS_ID]
        self.im = federation[IM_ID]

        self.entity_config_service = self.oc["federation_entity"].get_service(
            "entity_configuration")
        self.entity_config_service.upstream_get("context").issuer = AS_ID
        self.registration_service = self.oc["federation_entity"].get_service("registration")

    def test_automatic_registration_new_client_id(self):
        # No clients registered with the OP at the beginning
        assert len(self.oas['oauth_authorization_server'].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP gather some provider info discovery

        # Point the RP to the OP
        self.oc['oauth_client'].get_context().issuer = self.oas.entity_id

        # Create the URLs and messages that will be involved in this process
        _msgs = create_trust_chain_messages(self.oas, self.ta)

        # add the jwks_uri
        _jwks_uri = self.oas['oauth_authorization_server'].get_context().get_preference('jwks_uri')
        _msgs[_jwks_uri] = self.oas['oauth_authorization_server'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            self.oc['oauth_client'].do_request('provider_info')

        _context = self.oc['oauth_client'].get_context()
        # the provider info should have been updated
        assert _context.provider_info

        # automatic registration == not explict registration
        _context.map_supported_to_preferred(info=_context.provider_info)

        _auth_service = self.oc['oauth_client'].get_service('authorization')
        authn_request = _auth_service.construct(request_args={'response_type': 'code'})

        _msgs = create_trust_chain_messages(self.oc, self.im, self.ta)
        # add the jwks_uri
        _jwks_uri = self.oc['oauth_client'].get_context().get_preference('jwks_uri')
        _msgs[_jwks_uri] = self.oc['oauth_client'].keyjar.export_jwks_as_json()
        # https://op.example.org/static/jwks.json
        # _jwks_uri = self.oas['oauth_authorization_server'].get_context().get_preference(
        # 'jwks_uri')
        # _msgs[_jwks_uri] = self.oas['oauth_authorization_server'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # The OP handles the authorization request
            req = self.oas['oauth_authorization_server'].get_endpoint(
                'authorization').parse_request(
                authn_request.to_dict())

        assert "response_type" in req

        # Assert that the client's entity_id has been registered as a client
        assert self.oc.entity_id in self.oas['oauth_authorization_server'].get_context().cdb
