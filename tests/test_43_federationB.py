import pytest
import requests
import responses

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from tests import create_trust_chain_messages
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


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

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

        # intermediate

        INT = FederationEntityBuilder(
            IM_ID,
            metadata={
                "organization_name": "The organization",
                "homepage_uri": "https://example.com",
                "contacts": "operations@example.com"
            },
            key_conf = {"key_defs": KEYDEFS}
        )
        INT.add_services()
        INT.add_functions()
        INT.add_endpoints(metadata={"authority_hints": [TA_ID]})

        # Leaf RP

        RP = FederationEntityBuilder(
            RP_ID,
            metadata={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            key_conf={"key_defs": KEYDEFS}
        )
        RP.add_services()
        RP.add_functions()
        RP.add_endpoints(metadata={"authority_hints": [IM_ID]}, **LEAF_ENDPOINT)

        # Leaf OP

        OP = FederationEntityBuilder(
            OP_ID,
            metadata={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            key_conf={"key_defs": KEYDEFS}
        )
        OP.add_services()
        OP.add_functions()
        OP.add_endpoints(metadata={"authority_hints": [TA_ID]}, **LEAF_ENDPOINT)

        # TRUST ANCHOR
        self.ta = FederationEntity(**TA.conf, httpc=requests)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        # Intermediate
        INT.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR
        self.im = FederationEntity(**INT.conf, httpc=requests)

        # Leaf RP

        RP.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR
        self.rp = FederationEntity(**RP.conf)

        # Leaf OP
        OP.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR
        self.op = FederationEntity(**OP.conf)

        # TA subordinates == Intermediate and OP
        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        # intermediate subordinate = RP
        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'authority_hints': [IM_ID]
        }

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {OP_ID, IM_ID}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (leaf and TA) and 1 entity statement (TA about leaf
        # leaf = OP

        _msg = create_trust_chain_messages(self.rp, self.im, self.ta)

        assert len(_msg) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msg.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.op, RP_ID)

        assert len(chains) == 1
        assert len(chains[0]) == 2

        trust_chains = verify_trust_chains(self.op, chains, leaf_ec)
        assert trust_chains
        assert len(trust_chains) == 1

        trust_chains = apply_policies(self.op, trust_chains)
        assert trust_chains
        assert len(trust_chains) == 1

        trust_chain = trust_chains[0]
        assert trust_chain.metadata
        assert set(trust_chain.metadata.keys()) == {'federation_entity'}
        assert set(trust_chain.metadata['federation_entity'].keys()) == {
            'organization_name', 'homepage_uri', 'contacts'}
        assert trust_chain.metadata['federation_entity']["contacts"] == 'operations@rp.example.com'
