import pytest
import responses

from fedservice.build_entity import FederationEntityBuilder
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from tests import create_trust_chain_messages

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
del TA_ENDPOINTS["resolve"]


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
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

        # Leaf RP

        RP = FederationEntityBuilder(
            RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            key_conf={"key_defs": KEYDEFS},
            authority_hints=[TA_ID]
        )
        RP.add_services()
        RP.add_functions()
        RP.add_endpoints(**LEAF_ENDPOINT)

        # Leaf OP

        OP = FederationEntityBuilder(
            OP_ID,
            preference={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            key_conf={"key_defs": KEYDEFS},
            authority_hints=[TA_ID]
        )
        OP.add_services()
        OP.add_functions()
        OP.add_endpoints(**LEAF_ENDPOINT)

        self.ta = FederationEntity(**TA.conf)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        RP.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR
        self.rp = FederationEntity(**RP.conf)

        OP.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR
        self.op = FederationEntity(**OP.conf)

        self.ta.server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {OP_ID, RP_ID}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (leaf and TA) and 1 entity statement (TA about leaf
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
            'organization_name', 'homepage_uri', 'contacts'}

        assert trust_chain.is_expired() is False
