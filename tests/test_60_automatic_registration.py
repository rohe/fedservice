import os

import pytest
import responses
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo

from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.op import ServerEntity
from fedservice.op.authorization import Authorization
from fedservice.op.registration import Registration
from fedservice.rp import ClientEntity
from . import create_trust_chain_messages
from . import CRYPT_CONFIG
from .build_entity import FederationEntityBuilder

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]}
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
del TA_ENDPOINTS["resolve"]

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

        TA = FederationEntityBuilder(
            TA_ID,
            metadata={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_conf={"key_defs": KEYDEFS}
        )
        TA.add_endpoints(None, **TA_ENDPOINTS)

        self.ta = FederationEntity(**TA.conf)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        # intermediate

        INT = FederationEntityBuilder(
            IM_ID,
            metadata={
                "organization_name": "The organization",
                "homepage_uri": "https://example.com",
                "contacts": "operations@example.com"
            },
            key_conf={"key_defs": KEYDEFS},
            authority_hints=[TA_ID]
        )
        INT.add_services()
        INT.add_functions()
        INT.add_endpoints()

        # Intermediate
        self.im = FederationEntity(**INT.conf)

        ########################################
        # Leaf RP
        ########################################

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
        del oidc_service['web_finger']
        oidc_service['authorization'] = {"class": "fedservice.rp.authorization.Authorization"}

        RP_FE = FederationEntityBuilder(
            metadata={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            authority_hints=[IM_ID]
        )
        RP_FE.add_services()
        RP_FE.add_functions()
        RP_FE.add_endpoints(**LEAF_ENDPOINT)
        RP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR

        RP_CONFIG = {
            'entity_id': RP_ID,
            'key_conf': {"key_defs": KEYDEFS},  # One federation key set
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': RP_FE.conf
            },
            "openid_relying_party": {
                'class': ClientEntity,
                'kwargs': {
                    # OIDC core keys
                    "key_conf": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
                    'config': {
                        'client_id': RP_ID,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "metadata": {
                            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                            "id_token_signed_response_alg": "ES256",
                            "token_endpoint_auth_method": "client_secret_basic",
                            "token_endpoint_auth_signing_alg": "ES256",
                            "client_registration_types": ["automatic"],
                        },
                        "authorization_request_endpoints": [
                            'authorization_endpoint', 'pushed_authorization_request_endpoint'
                        ],
                        "add_ons": {
                            "pushed_authorization": {
                                "function": "idpyoidc.client.oauth2.add_on.pushed_authorization.add_support",
                                "kwargs": {
                                    "body_format": "jws",
                                    "signing_algorithm": "RS256",
                                    "http_client": None,
                                    "merge_rule": "lax",
                                },
                            }
                        },
                    },
                    "services": oidc_service
                }
            }
        }

        self.rp = FederationCombo(RP_CONFIG)

        ########################################
        # Leaf OP
        ########################################

        OP_FE = FederationEntityBuilder(
            metadata={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            authority_hints=[TA_ID]
        )
        OP_FE.add_services()
        OP_FE.add_functions()
        OP_FE.add_endpoints(**LEAF_ENDPOINT)
        OP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR

        OP_CONFIG = {
            'entity_id': OP_ID,
            'key_conf': {"key_defs": KEYDEFS},
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
                        "key_conf": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
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
                                    "response_modes_supported": ["query", "fragment", "form_post"],
                                    "claim_types_supported": [
                                        "normal",
                                        "aggregated",
                                        "distributed",
                                    ],
                                    "claims_parameter_supported": True,
                                    "request_parameter_supported": True,
                                    "request_uri_parameter_supported": True,
                                    "client_registration_types_supported": ['automatic', 'explicit']
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
                    }},
                'key_conf': {"key_defs": KEYDEFS},
                "services": oidc_service
            }
        }

        self.op = FederationCombo(OP_CONFIG)

        # Setup subordinates

        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]

        }

        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]

        }

        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'authority_hints': [IM_ID]
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
        _msgs[self.op['openid_provider'].endpoint_context.jwks_uri] = self.op[
            'openid_provider'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            self.rp['openid_relying_party'].do_request('provider_info')

        # the provider info should have been updated

        assert self.rp['openid_relying_party'].get_context().provider_info

        _auth_service = self.rp['openid_relying_party'].get_service('authorization')
        authn_request = _auth_service.construct()

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        # add the jwks_uri
        _msgs[self.rp['openid_relying_party'].get_context().jwks_uri] = self.rp[
            'openid_relying_party'].keyjar.export_jwks_as_json()

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

#     def test_automatic_registration_keep_client_id(self):
#         # This is cheating. Getting the OP provider info
#         _registration_service = self.service['registration']
#         _fe = _registration_service.client_get("service_context").federation_entity
#         statement = TrustChain()
#         statement.metadata = self.registration_endpoint.server_get(
#         "endpoint_context").provider_info
#         statement.anchor = "https://feide.no"
#         statement.verified_chain = [{'iss': "https://ntnu.no"}]
#
#         self.service['discovery'].update_service_context([statement])
#
#         _fe_context = self.rp_federation_entity.get_context()
#         # and the OP's federation keys
#         _fe_context.keyjar.import_jwks(
#             read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
#             issuer_id=self.registration_endpoint.server_get("endpoint_context").provider_info[
#                 'issuer'])
#
#         service_context = self.service['authorization'].client_get("service_context")
#         service_context.issuer = 'https://op.ntnu.no'
#         service_context.redirect_uris = ['https://foodle.uninett.no/callback']
#         service_context.entity_id = _fe_context.entity_id
#         service_context.client_id = _fe_context.entity_id
#         service_context.behaviour = {'response_types': ['code']}
#         service_context.provider_info = self.authorization_endpoint.server_get(
#             "endpoint_context").provider_info
#
#         authn_request = self.service['authorization'].construct()
#         # Have to provide the OP with clients keys
#         self.authorization_endpoint.server_get("endpoint_context").keyjar.import_jwks(
#             _registration_service.client_get("service_context").keyjar.export_jwks(),
#             ENTITY_ID
#         )
#
#         _auth_endp_context = self.authorization_endpoint.server_get("endpoint_context")
#         # get rid of the earlier client registrations
#         for k in _auth_endp_context.cdb.keys():
#             del _auth_endp_context.cdb[k]
#
#         # Have to provide the OP with clients keys
#         _auth_endp_context.keyjar.import_jwks(
#             _registration_service.client_get("service_context").keyjar.export_jwks(),
#             ENTITY_ID
#         )
#
#         # set new_id to False
#         self.authorization_endpoint.automatic_registration_endpoint.kwargs["new_id"] = False
#
#         # THe OP handles the authorization request
#         req = self.authorization_endpoint.parse_request(authn_request.to_dict())
#         assert "response_type" in req
#
#         # reg_resp = self.registration_endpoint.do_response(**res)
#         # assert set(reg_resp.keys()) == {'response', 'http_headers', 'cookie'}
#
#         client_ids = list(_auth_endp_context.cdb.keys())
#         assert len(client_ids) == 1
#         assert client_ids[0] == ENTITY_ID
#
#
# class TestAutomaticNoSupport(object):
#     @pytest.fixture(autouse=True)
#     def create_endpoint(self):
#         # First the RP
#         _config = copy.deepcopy(RP_CONFIG)
#         _config['behaviour'] = {
#             'federation_types_supported': ['explicit']
#         }
#         entity = FederationRP(config=_config)
#         self.rp_federation_entity = entity.client_get("service_context").federation_entity
#         # The test data collector
#         self.rp_federation_entity.collector = DummyCollector(
#             trusted_roots=ANCHOR, httpd=HTTPC, root_dir=os.path.join(BASE_PATH, 'base_data'))
#
#         entity._service = {
#             'discovery': FedProviderInfoDiscovery(entity.client_get),
#             'registration': Registration(entity.client_get),
#             'authorization': FedAuthorization(entity.client_get,
#                                               conf={"request_object_expires_in": 300}),
#         }
#         self.rp = entity
#
#         # and now for the OP
#         _config = copy.copy(OP_CONF)
#
#         server = FederationServer(_config)
#         self.registration_endpoint = server.server_get("endpoint", "registration")
#         self.authorization_endpoint = server.server_get("endpoint", "authorization")
#         self.provider_endpoint = server.server_get("endpoint", "provider_config")
#
#         federation_entity = server.server_get("endpoint_context").federation_entity
#         federation_entity.collector = DummyCollector(
#             httpd=Publisher(ROOT_DIR),
#             trusted_roots=ANCHOR,
#             root_dir=ROOT_DIR)
#
#     def test_automatic_registration_new_client_id(self):
#         _registration_service = self.rp.get_service('registration')
#
#         # This is cheating. Getting the OP's provider info
#         _fe = _registration_service.client_get("service_context").federation_entity
#         statement = TrustChain()
#         statement.metadata = self.registration_endpoint.server_get(
#         "endpoint_context").provider_info
#         statement.anchor = "https://feide.no"
#         statement.verified_chain = [{'iss': "https://ntnu.no"}]
#
#         self.rp.get_service('discovery').update_service_context([statement])
#         # and the OP's federation keys
#         self.rp_federation_entity.context.keyjar.import_jwks(
#             read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
#             issuer_id=self.registration_endpoint.server_get("endpoint_context").provider_info[
#                 'issuer'])
#
#         _context = self.rp.get_service('authorization').client_get("service_context")
#         _context.issuer = 'https://op.ntnu.no'
#         _context.redirect_uris = ['https://foodle.uninett.no/callback']
#         _context.entity_id = self.rp_federation_entity.context.entity_id
#         # _context.client_id = self.rp_federation_entity.entity_id
#         _context.behaviour = {'response_types': ['code']}
#         _context.provider_info = self.authorization_endpoint.server_get(
#             "endpoint_context").provider_info
#
#         # The client not registered and the OP not supporting automatic client registration
#         with pytest.raises(OtherError):
#             self.rp.get_service('authorization').construct()
