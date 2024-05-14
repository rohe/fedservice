import os

import pytest
import responses
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo

from fedservice.appserver.oidc.authorization import Authorization
from fedservice.appserver.oidc.registration import Registration
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from . import create_trust_chain_messages
from . import CRYPT_CONFIG

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]}
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

TA_ENDPOINTS = ["entity_configuration", "fetch", "metadata_verification"]

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}


class TestAutomatic(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

        # TRUST ANCHOR

        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=TA_ENDPOINTS
        )

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        # intermediate

        self.im = make_federation_entity(
            IM_ID,
            preference={
                "organization_name": "The organization",
                "homepage_uri": "https://example.com",
                "contacts": "operations@example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            trust_anchors=ANCHOR
        )
        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]

        }

        ########################################
        # Leaf RP
        ########################################

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
        oidc_service['authorization'] = {"class": "fedservice.appclient.oidc.authorization.Authorization"}

        self.rp = make_federation_combo(
            entity_id=RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            authority_hints=[IM_ID],
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            entity_type={
                "openid_relying_party": {
                    'class': "fedservice.appclient.ClientEntity",
                    'kwargs': {
                        # OIDC core keys
                        "key_conf": {"uri_path": "static/jwks.json", "key_defs": DEFAULT_KEY_DEFS},
                        'config': {
                            'base_url': RP_ID,
                            'client_id': RP_ID,
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
                        "services": oidc_service
                    }
                }
            }

        )

        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp["federation_entity"].keyjar.export_jwks(),
            'authority_hints': [IM_ID]
        }

        ########################################
        # Leaf OP
        ########################################

        self.op = make_federation_combo(
            entity_id=OP_ID,
            preference={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            authority_hints=[TA_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            entity_type={
                "openid_provider": {
                    'class': 'fedservice.appserver.ServerEntity',
                    'kwargs': {
                        'config': {
                            "issuer": "https://example.com/",
                            "httpc_params": {"verify": False, "timeout": 1},
                            "subject_types_supported": ["public", "pairwise", "ephemeral"],
                            "grant_types_supported": [
                                "authorization_code",
                                "implicit",
                                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                "refresh_token",
                            ],
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
                            "key_conf": {"key_defs": DEFAULT_KEY_DEFS,
                                         "uri_path": "static/jwks.json"},
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
                    "services": oidc_service
                }
            }
        )

        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op["federation_entity"].keyjar.export_jwks(),
            'authority_hints': [TA_ID]

        }

    def test_automatic_registration_new_client_id(self):
        # No clients registered with the OP at the beginning
        assert len(self.op['openid_provider'].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP gather some provider info discovery

        # Point the RP to the OP
        self.rp['openid_relying_party'].get_context().issuer = self.op.entity_id

        # Create the URLs and messages that will be involved in this process
        _msgs = create_trust_chain_messages(self.op, self.ta)

        # add the jwks_uri
        _jwks_uri = self.op['openid_provider'].get_context().get_preference('jwks_uri')
        _msgs[_jwks_uri] = self.op['openid_provider'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            self.rp['openid_relying_party'].do_request('provider_info')

        _context = self.rp['openid_relying_party'].get_context()
        # the provider info should have been updated
        assert _context.provider_info

        # automatic registration == not explict registration
        _context.map_supported_to_preferred(info=_context.provider_info)

        _auth_service = self.rp['openid_relying_party'].get_service('authorization')
        authn_request = _auth_service.construct(request_args={'response_type': 'code'})

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        # add the jwks_uri
        _jwks_uri = self.rp['openid_relying_party'].get_context().get_preference('jwks_uri')
        _msgs[_jwks_uri] = self.rp['openid_relying_party'].keyjar.export_jwks_as_json()
        # https://op.example.org/static/jwks.json
        # _jwks_uri = self.op['openid_provider'].get_context().get_preference('jwks_uri')
        # _msgs[_jwks_uri] = self.op['openid_provider'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # The OP handles the authorization request
            req = self.op['openid_provider'].get_endpoint('authorization').parse_request(
                authn_request.to_dict())

        assert "response_type" in req

        # Assert that the client's entity_id has been registered as a client
        assert self.rp.entity_id in self.op['openid_provider'].get_context().cdb

