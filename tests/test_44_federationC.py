from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo

import pytest
import responses

from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.op import ServerEntity
from fedservice.op.authorization import Authorization
from fedservice.op.registration import Registration
from fedservice.rp import ClientEntity
from tests import create_trust_chain_messages
from tests import CRYPT_CONFIG
from tests.build_entity import FederationEntityBuilder

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
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
            key_conf={"key_defs": KEYDEFS}
        )
        INT.add_services()
        INT.add_functions()
        INT.add_endpoints(metadata={"authority_hints": [TA_ID]})

        # Intermediate
        self.im = FederationEntity(**INT.conf)

        ########################################
        # Leaf RP
        ########################################

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
        del oidc_service['web_finger']

        RP_FE = FederationEntityBuilder(
            metadata={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
        )
        RP_FE.add_services()
        RP_FE.add_functions()
        RP_FE.add_endpoints(metadata={"authority_hints": [IM_ID]}, **LEAF_ENDPOINT)
        RP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR

        RP_CONFIG = {
            'entity_id': RP_ID,
            'key_conf': {"key_defs": KEYDEFS},
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': RP_FE.conf
            },
            "openid_relying_party": {
                'class': ClientEntity,
                'kwargs': {
                    'config': {
                        'client_id': RP_ID,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
                        "metadata": {
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

        self.rp = FederationCombo(RP_CONFIG)

        ########################################
        # Leaf OP
        ########################################

        OP_FE = FederationEntityBuilder(
            OP_ID,
            metadata={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            }
        )
        OP_FE.add_services()
        OP_FE.add_functions()
        OP_FE.add_endpoints(metadata={"authority_hints": [TA_ID]}, **LEAF_ENDPOINT)
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
            'organization_name', 'homepage_uri', 'contacts'}

    def test_provider_info_discovery(self):
        _rp = self.rp['openid_relying_party']
        _rp._service_context.issuer = self.op.entity_id
        provider_info = _rp.get_service('provider_info')

        # Just to verify that the request URL is the right one
        req = provider_info.get_request_parameters()
        assert req['url'] == 'https://op.example.org/.well-known/openid-federation?iss=https%3A%2F%2Fop.example.org'

        where_and_what = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            trust_chains = _rp.do_request('provider_info')

        assert len(trust_chains) == 1
        assert set(trust_chains[0].metadata.keys()) == {'federation_entity', 'openid_provider'}

    def test_create_explicit_registration_request(self):
        # phase 1 : the RP gathers the OpenID Providers metadata
        _rp = self.rp['openid_relying_party']
        _rp._service_context.issuer = self.op.entity_id
        provider_info = _rp.get_service('provider_info')

        # Just to verify that the request URL is the right one
        req = provider_info.get_request_parameters()
        assert req['url'] == 'https://op.example.org/.well-known/openid-federation?iss=https%3A%2F%2Fop.example.org'

        where_and_what = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _rp.do_request('provider_info')

        # Phase 2: The RP creates a registration request
        _rp = self.rp['openid_relying_party']
        _registration = _rp.get_service('registration')

        req = _registration.get_request_parameters()
        assert req['url'] == 'https://op.example.org/registration'

        where_and_what = create_trust_chain_messages(self.rp.entity_id, self.im, self.ta)

        # Phase 3: The OP receives a registration request and responds to it.

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _endpoint = self.op['openid_provider'].get_endpoint('registration')
            resp = _endpoint.process_request(req['body'])

        assert resp['response_code'] == 201
        _jws = factory(resp['response_msg'])
        _payload = _jws.jwt.payload()
        assert _payload['iss'] == self.op.entity_id
        assert _payload['sub'] == self.rp.entity_id
        assert _payload['trust_anchor_id'] == self.ta.entity_id
        assert _payload['aud'] == self.rp.entity_id

        # This is cached
        del where_and_what[f"{self.ta.entity_id}/.well-known/openid-federation"]

        # Phase 4: The RP receives the registration response and calculates the metadata
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            reg_resp = _registration.parse_response(resp['response_msg'])

        assert reg_resp
        assert 'client_id' in reg_resp