import pytest
import responses
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo

from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.op import ServerEntity
from fedservice.op.authorization import Authorization
from fedservice.op.registration import Registration
from fedservice.rp import ClientEntity
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages
from tests import CRYPT_CONFIG

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

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


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
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
            key_config={"key_defs": KEYDEFS},
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
            key_config={"key_defs": KEYDEFS},
            authority_hints=[TA_ID],
            endpoints=["entity_configuration", "fetch", "list"],
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

        self.rp = make_federation_combo(
            RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            authority_hints=[IM_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            entity_type={
                "openid_relying_party": {
                    'class': ClientEntity,
                    'kwargs': {
                        'config': {
                            'client_id': RP_ID,
                            'client_secret': 'a longesh password',
                            'redirect_uris': ['https://example.com/cli/authz_cb'],
                            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
                            "preference": {
                                "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                                "id_token_signed_response_alg": "ES256",
                                "token_endpoint_auth_method": "client_secret_basic",
                                "token_endpoint_auth_signing_alg": "ES256"
                            }
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
            OP_ID,
            preference={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            authority_hints=[TA_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            entity_type={
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
                            "keys": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
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
                    }
                }
            }
        )
        # Setup subordinates

        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op["federation_entity"].keyjar.export_jwks(),
            'authority_hints': [TA_ID]

        }

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {OP_ID, IM_ID}

        assert self.op
        assert set(self.op.keys()) == {'federation_entity', 'openid_provider'}

        assert self.rp
        assert set(self.rp.keys()) == {'federation_entity', 'openid_relying_party'}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (leaf and TA) and 1 entity statement (TA about leaf)
        # leaf = OP

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)

        assert len(_msgs) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.op, RP_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.rp, chains, leaf_ec)
        trust_chains = apply_policies(self.rp, trust_chains)
        assert len(trust_chains) == 1

        trust_chain = trust_chains[0]

        assert trust_chain.metadata
        assert set(trust_chain.metadata.keys()) == {'federation_entity', 'openid_relying_party'}
        assert set(trust_chain.metadata['federation_entity'].keys()) == {
            'organization_name', 'homepage_uri', 'contacts', "jwks"}

    def test_provider_info_discovery(self):
        _rp = self.rp['openid_relying_party']
        _rp.get_context().issuer = self.op.entity_id
        provider_info = _rp.get_service('provider_info')

        # Just to verify that the request URL is the right one
        req = provider_info.get_request_parameters()
        assert req[
                   'url'] == 'https://op.example.org/.well-known/openid-federation?iss=https%3A%2F%2Fop.example.org'

        where_and_what = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            trust_chains = _rp.do_request('provider_info')

        assert len(trust_chains) == 1
        assert set(trust_chains[0].metadata.keys()) == {'federation_entity', 'openid_provider'}
