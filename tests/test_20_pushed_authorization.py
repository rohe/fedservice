import os

from cryptojwt import JWT
from oidcmsg.defaults import JWT_BEARER
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.server.cookie_handler import CookieHandler
from oidcmsg.server.oidc.provider_config import ProviderConfiguration
from oidcmsg.server.oidc.registration import Registration as OPRegistration
from oidcmsg.server.token.id_token import IDToken
import pytest

from fedservice.entity.fetch import Fetch
from fedservice.entity_statement.statement import TrustChain
from fedservice.fetch_entity_statement.fs2 import read_info
from fedservice.op import FederationServer
from fedservice.op.authorization import Authorization
from fedservice.op.pushed_authorization import PushedAuthorization
from fedservice.rp import FederationRP
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

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]}
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

CLIENTS = {
    "oidc_clients": {
        "s6BhdRkqt3": {
            "client_secret": "7Fjfp0ZBr1KtDRbnfVdmIw",
            "redirect_uris": [['https://client.example.org/cb', '']],
            "client_salt": "salted",
            'token_endpoint_auth_method': ['client_secret_post'],
            'response_types': ['code', 'token', 'code id_token', 'id_token', 'code id_token token']
        }
    }
}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_setup(self):
        # First the RP
        config = {
            'behaviour': {
                'federation_types_supported': ['automatic']
            },
            'issuer': "https://op.ntnu.no",
            'keys': {'key_defs': KEYSPEC},
            "federation": {
                "endpoint": {
                    "fetch": {
                        "path": "fetch",
                        "class": Fetch,
                        "kwargs": {"client_authn_method": None},
                    }
                },
                'entity_id': RP_ENTITY_ID,
                "trusted_roots": ANCHOR,
                "authority_hints": ['https://ntnu.no'],
                "entity_type": 'openid_relying_party',
                "opponent_entity_type": 'openid_provider'
            }
        }

        self.entity = FederationRP(config=config)
        service_context = self.entity.get_service_context()

        service_context.federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, root_dir=ROOT_DIR)

        # The RP has/supports 2 services
        self.discovery_service = FedProviderInfoDiscovery(self.entity.client_get)
        self.registration_service = RPRegistration(self.entity.client_get)
        # self.authorization_service = FedAuthorization(entity.client_get)

        # and now for the OP
        op_entity_id = "https://op.ntnu.no"
        op_conf = {
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
                    "class": "oidcmsg.server.token.jwt_token.JWTToken",
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
            "claims_interface": {"class": "oidcmsg.server.session.claims.ClaimsInterface",
                                 "kwargs": {}},
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
                    "class": "oidcmsg.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {
                    "keys": {"key_defs": COOKIE_KEYDEFS},
                    "name": {
                        "session": "oidc_op",
                        "register": "oidc_op_reg",
                        "session_management": "oidc_op_sman"
                    }
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
            },
            "federation": {
                "endpoint": {
                    "fetch": {
                        "path": "fetch",
                        "class": Fetch,
                        "kwargs": {"client_authn_method": None},
                    }
                },
                "entity_id": op_entity_id,
                "trusted_roots": ANCHOR,
                "authority_hints": ['https://ntnu.no'],
                "entity_type": 'openid_relying_party',
                "opponent_entity_type": 'openid_relying_party'
            }
        }
        server = FederationServer(conf=op_conf)
        endpoint_context = server.get_endpoint_context()
        # _clients = yaml.safe_load(io.StringIO(client_yaml))
        # endpoint_context.cdb = _clients["oidc_clients"]
        # store keys under my own ID
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), op_conf["issuer"]
        )

        self.pushed_authorization_endpoint = server.server_get("endpoint", "pushed_authorization")
        self.authorization_endpoint = server.server_get("endpoint", "authorization")
        self.registration_endpoint = server.server_get("endpoint", "registration")

        endpoint_context.federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

    def test_pushed_auth_urlencoded(self):
        # since all endpoint used the same endpoint_context I can grab anyone
        _op_context = self.registration_endpoint.server_get("endpoint_context")

        # This is cheating. Getting the OP's provider info
        _fe = self.registration_service.client_get("service_context").federation_entity
        trust_chain = TrustChain()
        trust_chain.metadata = _op_context.provider_info
        trust_chain.anchor = "https://feide.no"
        trust_chain.verified_chain = [{'iss': "https://ntnu.no"}]

        self.discovery_service.update_service_context([trust_chain])
        # and the OP's federation keys
        _op_context.federation_entity.context.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=_op_context.provider_info['issuer'])

        # Add RP's OIDC keys to the OP's keyjar.
        _op_context.keyjar.import_jwks(
            self.discovery_service.client_get("service_context").keyjar.export_jwks(issuer_id=""),
            RP_ENTITY_ID
        )

        authn_request = AuthorizationRequest(
            response_type="code", state="af0ifjsldkj",
            client_id=RP_ENTITY_ID, redirect_uri="{}/callback".format(RP_ENTITY_ID),
            code_challenge="K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
            code_challenge_method="S256", scope=["ais", "openid"]
        )

        # Create the private_key_jwt assertion
        _jwt = JWT(self.registration_service.client_get("service_context").keyjar,
                   iss=RP_ENTITY_ID,
                   sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack(
            {
                "aud": [_op_context.provider_info["pushed_authorization_request_endpoint"]]
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
        assert set(_op_context.cdb.keys()) == {RP_ENTITY_ID}

    def test_pushed_auth_urlencoded_process(self):
        # since all endpoint used the same endpoint_context I can grab anyone
        _context = self.registration_endpoint.server_get("endpoint_context")

        # This is cheating. Getting the OP's provider info
        _fe = self.registration_service.client_get("service_context").federation_entity
        trust_chain = TrustChain()
        trust_chain.metadata = _context.provider_info
        trust_chain.anchor = "https://feide.no"
        trust_chain.verified_chain = [{'iss': "https://ntnu.no"}]

        self.discovery_service.update_service_context([trust_chain])

        _rp_context = self.discovery_service.client_get("service_context")
        # add the OP's federation keys to the RP
        _rp_context.federation_entity.context.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=_context.provider_info['issuer'])

        # Add RP's keys to the OP's OIDC keyjar.
        _context.keyjar.import_jwks(
            _rp_context.keyjar.export_jwks(issuer_id=""),
            RP_ENTITY_ID
        )

        authn_request = AuthorizationRequest(
            response_type="code", state="af0ifjsldkj",
            client_id=RP_ENTITY_ID, redirect_uri="{}/callback".format(RP_ENTITY_ID),
            code_challenge="K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
            code_challenge_method="S256", scope=["ais", "openid"]
        )

        # Create the private_key_jwt assertion
        _jwt = JWT(self.registration_service.client_get("service_context").keyjar,
                   iss=RP_ENTITY_ID,
                   sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack(
            {
                "aud": [_context.provider_info[
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
