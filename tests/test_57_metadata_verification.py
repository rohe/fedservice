import os

import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.server.configure import DEFAULT_OIDC_ENDPOINTS

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import FEDERATION_ENTITY_FUNCTIONS
from fedservice.defaults import FEDERATION_ENTITY_SERVICES
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.defaults import WELL_KNOWN_FEDERATION_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.op import ServerEntity
from fedservice.rp import ClientEntity
from . import create_trust_chain_messages
from . import CRYPT_CONFIG

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

TA_ENDPOINTS = {
    "entity_configuration": {
        "path": ".well-known/openid-federation",
        "class": "fedservice.entity.server.entity_configuration.EntityConfiguration",
        "kwargs": {}
    },
    "fetch": {
        "path": "fetch",
        "class": "fedservice.entity.server.fetch.Fetch",
        "kwargs": {}
    },
    "metadata_verification": {
        "path": "verifier",
        "class": "fedservice.entity.server.metadata_verification.MetadataVerification",
        "kwargs": {}
    }
}

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


class TestExplicit(object):

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
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_conf={"key_defs": DEFAULT_KEY_DEFS}
        )
        TA.add_endpoints(None, **TA_ENDPOINTS)

        self.ta = FederationEntity(**TA.conf)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        # intermediate

        INT = FederationEntityBuilder(
            IM_ID,
            preference={
                "organization_name": "The organization",
                "homepage_uri": "https://example.com",
                "contacts": "operations@example.com"
            },
            key_conf={"key_defs": DEFAULT_KEY_DEFS},
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
        # del oidc_service['web_finger']
        oidc_service['authorization'] = {
            "class": "fedservice.rp.authorization.Authorization"}

        RP_FE = FederationEntityBuilder(
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            authority_hints=[IM_ID],
            key_conf={"key_defs": DEFAULT_KEY_DEFS}
        )
        _services = FEDERATION_ENTITY_SERVICES.copy()
        _services["metadata_verification"] = {
            "class": 'fedservice.entity.client.metadata_verification.MetadataVerification',
            "kwargs": {}
        }
        RP_FE.add_services(**_services)
        _functions = FEDERATION_ENTITY_FUNCTIONS.copy()
        _functions["metadata_verification"] = {
            'class': 'fedservice.entity.function.metadata_verifier.MetadataVerifier',
            'kwargs': {"metadata_verifier_id": TA_ID}
        }

        RP_FE.add_functions(**_functions)
        RP_FE.add_endpoints(**LEAF_ENDPOINT)
        RP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR

        RP_CONFIG = {
            'entity_id': RP_ID,
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': RP_FE.conf
            },
            "openid_relying_party": {
                'class': ClientEntity,
                'kwargs': {
                    # OIDC core keys
                    "key_conf": {"uri_path": "static/jwks.json", "key_defs": DEFAULT_KEY_DEFS},
                    'config': {
                        'client_id': RP_ID,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "preference": {
                            "grant_types": ['authorization_code', 'implicit',
                                            'refresh_token'],
                            "id_token_signed_response_alg": "ES256",
                            "token_endpoint_auth_method": "client_secret_basic",
                            "token_endpoint_auth_signing_alg": "ES256",
                            "client_registration_types": ["explicit"],
                        },
                    },
                    "services": oidc_service,
                    'client_type': 'oidc'
                }
            }
        }

        self.rp = FederationCombo(RP_CONFIG)

        ########################################
        # Leaf OP
        ########################################

        OP_FE = FederationEntityBuilder(
            preference={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            authority_hints=[TA_ID],
            key_conf={"key_defs": DEFAULT_KEY_DEFS},
        )
        _endpoints = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
        _endpoints["metadata_verification"] = {
            "path": "metadata_verification",
            "class": 'fedservice.entity.server.metadata_verification.MetadataVerification',
            "kwargs": {}
        }
        OP_FE.add_services()
        OP_FE.add_functions()
        OP_FE.add_endpoints(**_endpoints)
        OP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR

        _endpoints = DEFAULT_OIDC_ENDPOINTS.copy()
        _endpoints["register"] = {
            "path": "registration",
            "class": "fedservice.op.registration.Registration",
            "kwargs": {}
        }
        OP_CONFIG = {
            'entity_id': OP_ID,
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
                        "preferences": {
                            "subject_types_supported": ["public", "pairwise", "ephemeral"],
                            "grant_types_supported": [
                                "authorization_code",
                                "implicit",
                                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                "refresh_token",
                            ],
                        },
                        "key_conf": {
                            "key_defs": DEFAULT_KEY_DEFS,
                            "uri_path": "static/jwks.json"},
                        "template_dir": "template",
                        "session_params": SESSION_PARAMS,
                        "endpoint": _endpoints
                    }
                }
            }
        }

        self.op = FederationCombo(OP_CONFIG)

        # Setup TA subordinates

        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'entity_types': ['federation_entity']

        }

        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op['federation_entity'].keyjar.export_jwks(),
            'entity_types': ['federation_entity', 'openid_provider']
        }

        # Intermediate's subordinate

        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp['federation_entity'].keyjar.export_jwks(),
            'entity_types': ['federation_entity', 'openid_relying_party']
        }

    def test_registration_verification(self):
        # No clients registered with the OP at the beginning
        assert len(self.op['openid_provider'].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP do some provider info discovery
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
                         headers={"Content-Type": "application/json"}, status=200)

            self.rp['openid_relying_party'].do_request('provider_info')

        # the provider info should have been updated

        assert self.rp['openid_relying_party'].get_context().provider_info

        ####################################################
        # [2] Let the RP construct the registration request

        _reg_service = self.rp['openid_relying_party'].get_service('registration')
        reg_request = _reg_service.construct()

        ###############################################################
        # [3] The OP receives a registration request and responds to it
        _msgs = create_trust_chain_messages(self.rp.entity_id, self.im, self.ta)
        # add the jwks_uri
        # _jwks_uri = self.op['openid_provider'].get_preference('jwks_uri')
        # _msgs[_jwks_uri] = self.op['openid_provider'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         headers={"Content-Type": "application/json"}, status=200)

            # The OP handles the registration request
            resp = self.op['openid_provider'].get_endpoint('registration').process_request(
                reg_request)

        assert resp["response_code"] == 201

        _jws = factory(resp['response_msg'])
        _payload = _jws.jwt.payload()
        assert _payload['iss'] == self.op.entity_id
        assert _payload['sub'] == self.rp.entity_id
        assert _payload['trust_anchor_id'] == self.ta.entity_id
        assert _payload['aud'] == self.rp.entity_id

        ###########################################################################
        # [4] The RP receives the registration response and calculates the preference

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        del _msgs[WELL_KNOWN_FEDERATION_ENDPOINT.format(self.ta.entity_id)]
        # _msgs = {}

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         headers={"Content-Type": "application/json"}, status=200)

            reg_resp = _reg_service.parse_response(resp['response_msg'])

        assert reg_resp
        assert 'client_id' in reg_resp
