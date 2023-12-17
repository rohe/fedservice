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

TA_ENDPOINTS = ["entity_configuration", "fetch", "list"]


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": KEYDEFS}
        )

        # Leaf RP

        self.rp = make_federation_entity(
            RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            authority_hints=[TA_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors={TA_ID: self.ta.keyjar.export_jwks()}
        )
        self.ta.server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
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
            endpoints=LEAF_ENDPOINTS,
            trust_anchors={TA_ID: self.ta.keyjar.export_jwks()}
        )

        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {OP_ID, RP_ID}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (leaf and TA) and 1 entity statement (TA about the leaf)
        # leaf = OP

        _msgs = create_trust_chain_messages(self.op, self.ta)

        assert len(_msgs) == 3

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.rp, OP_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.rp, chains, leaf_ec)
        trust_chains = apply_policies(self.rp, trust_chains)
        assert len(trust_chains) == 1

        trust_chain = trust_chains[0]

        assert trust_chain.metadata
        assert set(trust_chain.metadata.keys()) == {'federation_entity'}
        assert set(trust_chain.metadata['federation_entity'].keys()) == {
            "organization_name", "homepage_uri", "contacts", "jwks"}

        assert trust_chain.is_expired() is False

    def test_collect_trust_chain_2(self):
        # Trust chain OP->TA
        _msgs = create_trust_chain_messages(self.op, self.ta)

        assert len(_msgs) == 3

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.rp, OP_ID)

        assert len(chains) == 1

        # Trust chain RP->TA
        _msgs = create_trust_chain_messages(self.rp, self.ta)

        del _msgs['https://ta.example.org/.well-known/openid-federation']
        assert len(_msgs) == 2

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains_1, leaf_ec_1 = collect_trust_chains(self.rp, RP_ID)

        assert len(chains_1) == 1

        # Trust chain RP->TA Second time
        chains_2, leaf_ec_2 = collect_trust_chains(self.rp, RP_ID)

        assert leaf_ec_2
        assert leaf_ec_1 == leaf_ec_2
        assert chains_1 == chains_2