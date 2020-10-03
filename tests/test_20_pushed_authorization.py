import io
import os

import pytest
import yaml
from cryptojwt import JWT
from oidcendpoint.cookie import CookieDealer
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.id_token import IDToken
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration as OPRegistration
from oidcmsg.oauth2 import AuthorizationRequest
from oidcservice import JWT_BEARER
from oidcservice.service_context import ServiceContext

from fedservice import FederationEntity
from fedservice.entity_statement.statement import Statement
from fedservice.metadata_api.fs2 import read_info
from fedservice.op.authorization import Authorization
from fedservice.op.pushed_authorization import PushedAuthorization
from fedservice.rp.authorization import FedAuthorization
from fedservice.rp.provider_info_discovery import FedProviderInfoDiscovery
from fedservice.rp.registration import Registration as RPRegistration
from .utils import DummyCollector
from .utils import Publisher

CAPABILITIES = {
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

RP_ENTITY_ID = 'https://foodle.uninett.no'

ANCHOR = {'https://feide.no': read_info(os.path.join(ROOT_DIR, 'feide.no'), "feide.no", "jwks")}

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

client_yaml = """
oidc_clients:
  s6BhdRkqt3:
    "client_secret": 7Fjfp0ZBr1KtDRbnfVdmIw
    "redirect_uris": 
        - ['https://client.example.org/cb', '']
    "client_salt": "salted"
    'token_endpoint_auth_method': 'client_secret_post'
    'response_types': 
        - 'code'
        - 'token'
        - 'code id_token'
        - 'id_token'
        - 'code id_token token'
"""


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_setup(self):
        # First the RP
        service_context = ServiceContext(config={
                                             'behaviour': {
                                                 'federation_types_supported': ['automatic']
                                             },
                                             'issuer': "https://op.ntnu.no",
                                             'keys': {'key_defs': KEYSPEC}
                                         })

        self.rp_federation_entity = FederationEntity(
            entity_id=RP_ENTITY_ID, trusted_roots=ANCHOR, authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party', opponent_entity_type='openid_provider'
        )

        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'foodle.uninett.no'),
                      'foodle.uninett.no', 'jwks'), issuer_id=RP_ENTITY_ID)

        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, root_dir=ROOT_DIR)

        # add the federation part to the service context
        service_context.federation_entity = self.rp_federation_entity

        # The RP has/supports 2 services
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context),
            'registration': RPRegistration(service_context),
            'authorization': FedAuthorization(service_context),
        }

        # and now for the OP
        op_entity_id = "https://op.ntnu.no"
        conf = {
            "issuer": op_entity_id,
            "password": "mycket hemligt zebra",
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "code"},
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "refresh"},
                    ],
                },
                "code": {"lifetime": 600},
                "token": {
                    "class": "oidcendpoint.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims": [
                            "email",
                            "email_verified",
                            "phone_number",
                            "phone_number_verified",
                        ],
                        "add_claim_by_scope": True,
                        "aud": ["https://example.org/appl"]
                    },
                },
                "refresh": {"lifetime": 86400},
            },
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYSPEC},
            "id_token": {
                "class": IDToken,
                "kwargs": {
                    "default_claims": {
                        "email": {"essential": True},
                        "email_verified": {"essential": True},
                    }
                },
            },
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "registration",
                    "class": OPRegistration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "authorization",
                    "class": Authorization,
                    "kwargs": {
                        "response_types_supported": [
                            " ".join(x) for x in RESPONSE_TYPES_SUPPORTED
                        ],
                        "response_modes_supported": ["query", "fragment", "form_post"],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                    },
                },
                "pushed_authorization": {
                    "path": "pushed_authorization",
                    "class": PushedAuthorization,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
            },
            "authentication": {
                "anon": {
                    "acr": "http://www.swamid.se/policy/assurance/al1",
                    "class": "oidcendpoint.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "cookie_dealer": {
                "class": CookieDealer,
                "kwargs": {
                    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                    "default_values": {
                        "name": "oidcop",
                        "domain": "127.0.0.1",
                        "path": "/",
                        "max_age": 3600,
                    },
                },
            },
            'add_on': {
                "automatic_registration": {
                    "function":
                        "fedservice.op.add_on.automatic_registration.add_support",
                    "kwargs": {
                        "new_id": False,  # default False
                        "where": ["pushed_authorization"]
                    }
                }
            }
        }
        endpoint_context = EndpointContext(conf)
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        # endpoint_context.cdb = _clients["oidc_clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )

        self.pushed_authorization_endpoint = endpoint_context.endpoint[
            "pushed_authorization"
        ]
        self.authorization_endpoint = endpoint_context.endpoint["authorization"]
        self.registration_endpoint = endpoint_context.endpoint["registration"]

        federation_entity = FederationEntity(
            op_entity_id, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party',
            httpd=Publisher(ROOT_DIR),
            opponent_entity_type='openid_relying_party')

        federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'),
                      'op.ntnu.no', 'jwks'),
            issuer_id=op_entity_id)

        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.authorization_endpoint.endpoint_context.federation_entity = federation_entity

    def test_pushed_auth_urlencoded(self):
        # This is cheating. Getting the OP's provider info
        _fe = self.service['registration'].service_context.federation_entity
        statement = Statement()
        statement.metadata = self.registration_endpoint.endpoint_context.provider_info
        statement.fo = "https://feide.no"
        statement.verified_chain = [{'iss': "https://ntnu.no"}]

        self.service['discovery'].update_service_context([statement])
        # and the OP's federation keys
        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.endpoint_context.provider_info['issuer'])

        # Add RP's keys to the OP's keyjar.
        self.registration_endpoint.endpoint_context.keyjar.import_jwks(
            self.service["discovery"].service_context.keyjar.export_jwks(issuer_id=""), RP_ENTITY_ID
        )

        authn_request = AuthorizationRequest(
            response_type="code", state="af0ifjsldkj",
            client_id=RP_ENTITY_ID, redirect_uri="{}/callback".format(RP_ENTITY_ID),
            code_challenge="K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
            code_challenge_method="S256", scope=["ais", "openid"]
        )

        # Create the private_key_jwt assertion
        _jwt = JWT(self.service['registration'].service_context.keyjar,
                   iss=RP_ENTITY_ID,
                   sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack(
            {
                "aud": [self.pushed_authorization_endpoint.endpoint_context.provider_info[
                            "pushed_authorization_request_endpoint"]]
            })
        authn_request.update({"client_assertion": _assertion, "client_assertion_type": JWT_BEARER})

        _req = self.pushed_authorization_endpoint.parse_request(authn_request)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "state",
            "redirect_uri",
            "response_type",
            "scope",
            "code_challenge_method",
            "client_id",
            "code_challenge",
            "client_assertion",
            "client_assertion_type",
            '__verified_client_assertion'
        }

        # Should have a registered client now
        assert set(self.authorization_endpoint.endpoint_context.cdb.keys()) == {RP_ENTITY_ID}


    def test_pushed_auth_urlencoded_process(self):
        # This is cheating. Getting the OP's provider info
        _fe = self.service['registration'].service_context.federation_entity
        statement = Statement()
        statement.metadata = self.registration_endpoint.endpoint_context.provider_info
        statement.fo = "https://feide.no"
        statement.verified_chain = [{'iss': "https://ntnu.no"}]

        self.service['discovery'].update_service_context([statement])
        # and the OP's federation keys
        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.endpoint_context.provider_info['issuer'])

        # Add RP's keys to the OP's keyjar.
        self.registration_endpoint.endpoint_context.keyjar.import_jwks(
            self.service["discovery"].service_context.keyjar.export_jwks(issuer_id=""), RP_ENTITY_ID
        )

        authn_request = AuthorizationRequest(
            response_type="code", state="af0ifjsldkj",
            client_id=RP_ENTITY_ID, redirect_uri="{}/callback".format(RP_ENTITY_ID),
            code_challenge="K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
            code_challenge_method="S256", scope=["ais", "openid"]
        )

        # Create the private_key_jwt assertion
        _jwt = JWT(self.service['registration'].service_context.keyjar,
                   iss=RP_ENTITY_ID,
                   sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack(
            {
                "aud": [self.pushed_authorization_endpoint.endpoint_context.provider_info[
                            "pushed_authorization_request_endpoint"]]
            })
        authn_request.update({"client_assertion": _assertion, "client_assertion_type": JWT_BEARER})

        _req = self.pushed_authorization_endpoint.parse_request(authn_request)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "state",
            "redirect_uri",
            "response_type",
            "scope",
            "code_challenge_method",
            "client_id",
            "code_challenge",
            "client_assertion",
            "client_assertion_type",
            "__verified_client_assertion"
        }

        _resp = self.pushed_authorization_endpoint.process_request(_req)

        assert _resp["return_uri"] == authn_request["redirect_uri"]

        # And now for the authorization request with the OP provided request_uri

        authn_request["request_uri"] = _resp["http_response"]["request_uri"]
        for parameter in ["code_challenge", "code_challenge_method", "client_assertion",
                          "client_assertion_type"]:
            del authn_request[parameter]

        _req = self.authorization_endpoint.parse_request(authn_request)

        assert "code_challenge" in _req
