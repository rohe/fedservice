import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.rp import ClientEntity
from tests import create_trust_chain_messages

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TA_ID = "https://ta.example.org"
LEAF_ID = "https://leaf.example.org"
IM_ID = "https://im.example.org"
RP_ID = "https://rp.example.org"

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
del TA_ENDPOINTS["resolve"]


class TestConstraints(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #          TA
        #          |
        #          IM      OP
        #          |
        #       +--+--+
        #       |     |
        #      RP   LEAF

        # TRUST ANCHOR

        TA = FederationEntityBuilder(
            TA_ID,
            preference={
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
            preference={
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
        # Leaf
        ########################################

        LEAF = FederationEntityBuilder(
            LEAF_ID,
            preference={
                "organization_name": "A leaf",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_conf={"key_defs": KEYDEFS},
            authority_hints=[IM_ID]
        )
        LEAF.add_services()
        LEAF.add_functions()
        LEAF.add_endpoints(**LEAF_ENDPOINT)
        LEAF.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR

        self.leaf = FederationEntity(**LEAF.conf)

        ########################################
        # Leaf RP
        ########################################

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)

        RP_FE = FederationEntityBuilder(
            RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            authority_hints=[IM_ID]
        )
        RP_FE.add_services()
        RP_FE.add_functions()
        RP_FE.add_endpoints({}, **LEAF_ENDPOINT)
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
                        "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                        "id_token_signed_response_alg": "ES256",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "token_endpoint_auth_signing_alg": "ES256"
                    },
                    "services": oidc_service
                }
            }
        }

        self.rp = FederationCombo(RP_CONFIG)

        # downward chain
        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks()
        }
        self.im.server.subordinate[LEAF_ID] = {
            "jwks": self.leaf.keyjar.export_jwks(),
            'entity_types': ['federation_entity']
        }
        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'entity_types': ['openid_relying_party', 'federation_entity']
        }

        # Policies
        # entity specific
        self.ta.server.policy[IM_ID] = {
            "metadata_policy": {
                "openid_relying_party": {
                    "application_type": {
                        "one_of": ["web", "native"]
                    },
                    "grant_types": {
                        "subset_of": ["authorization_code", "refresh_token"]
                    }
                },
                'federation_entity': {
                    "contacts": {
                        'add': ['ops@ta.example.com']
                    }
                }
            }
        }
        # entity type specific
        self.im.server.policy['openid_relying_party'] = {
            "metadata_policy": {
                "contacts": {
                    "add": ["ops@example.org", "ops@example.com"]
                },
                "grant_types": {
                    "subset_of": ["authorization_code", "refresh_token"]
                }
            },
            'metadata': {
                "application_type": "web",
                "organization_name": "EXAMPLE INC.",
                "logo_uri": "https://www.example.com/images/32x32.png",
            }
        }

    def test_intermediate(self):
        _endpoint = self.ta.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'iss': self.ta.entity_id, 'sub': self.im.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        assert 'metadata_policy' in _payload

        _msgs = create_trust_chain_messages(self.im, self.ta)

        assert len(_msgs) == 3

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.leaf, IM_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, leaf_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        assert 'ops@ta.example.com' in trust_chains[0].metadata['federation_entity']['contacts']

    def test_leaf(self):
        _endpoint = self.im.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'sub': self.leaf.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        # The intermediate has no specific policy for the leaf and none general for entity types
        assert 'metadata_policy' not in _payload and 'metadata' not in _payload

        _msgs = create_trust_chain_messages(self.leaf, self.im, self.ta)

        assert len(_msgs) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.leaf, LEAF_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, leaf_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        assert 'ops@ta.example.com' in trust_chains[0].metadata['federation_entity']['contacts']

    def test_rp(self):
        _endpoint = self.im.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'sub': self.rp.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        assert 'metadata_policy' in _payload and 'metadata' in _payload

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)

        assert len(_msgs) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, rp_ec = collect_trust_chains(self.leaf, RP_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, rp_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        _metadata = trust_chains[0].metadata

        assert 'ops@ta.example.com' in _metadata['federation_entity']['contacts']
        assert _metadata['openid_relying_party']['grant_types'] == ['authorization_code']
