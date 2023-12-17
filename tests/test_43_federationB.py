import pytest
import responses

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

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

        ANCHOR = {self.ta.entity_id: self.ta.keyjar.export_jwks()}

        # Leaf RP

        self.rp = make_federation_entity(
            RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            authority_hints=[IM_ID],
            trust_anchors=ANCHOR,
            endpoints=LEAF_ENDPOINTS
        )

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
            trust_anchors=ANCHOR,
            endpoints=["entity_configuration", "fetch", "list"],
            subordinate={
                RP_ID: {
                    "jwks": self.rp.keyjar.export_jwks(),
                    'authority_hints': [IM_ID]
                }
            },
            metadata_policy={
                RP_ID: {
                    "federation_entity": {
                        "organization_name": {"value": "Example Inc."}
                    }
                }
            }
        )

        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        # Leaf OP

        self.op = make_federation_entity(
            OP_ID,
            preference={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            authority_hints=[TA_ID],
            trust_anchors={self.ta.entity_id: self.ta.keyjar.export_jwks()},
            endpoints=LEAF_ENDPOINTS
        )
        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
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
            'organization_name', 'homepage_uri', 'contacts', "jwks"}
        assert trust_chain.metadata['federation_entity']["contacts"] == 'operations@rp.example.com'
