import pytest
import responses
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.util import rndstr

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.trust_mark_entity.trust_mark_issuer import create_trust_mark
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
TRUST_MARK_ISSUER_ID = "https://trust_mark_issuer.example.org"
IM_ID = "https://im.example.org"

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #     Federation tree
        #
        #            TA
        #        +---|-------+
        #        |           |
        #        IM      TRUST_MARK_ISSUER
        #        |
        #        RP

        ########################################
        # Trust Anchor
        ########################################

        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=TA_ENDPOINTS
        )

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        ########################################
        # intermediate
        ########################################

        self.im = make_federation_entity(
            IM_ID,
            preference={
                "organization_name": "The organization",
                "homepage_uri": "https://example.com",
                "contacts": "operations@example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
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

        self.rp = make_federation_entity(
            RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            trust_anchors=ANCHOR,
            endpoints=LEAF_ENDPOINTS
        )
        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'authority_hints': [IM_ID]
        }

        ########################################
        # Trust Mark Issuer
        ########################################

        self.tmi = make_federation_entity(
            entity_id=TRUST_MARK_ISSUER_ID,
            key_config={'key_defs': DEFAULT_KEY_DEFS},
            preference={
                "organization_name": "The Trust Mark Issuer",
                "homepage_uri": "https://tmi.example.com",
                "contacts": "operations@tmi.example.com"
            },
            authority_hints=[TA_ID],
            endpoints=["entity_configuration", "status"],
            trust_anchors=ANCHOR,
            item_args={
                "endpoint": {
                    "status": {
                        "trust_mark_issuer": {
                            "class": "fedservice.trust_mark_issuer.TrustMarkIssuer",
                            "kwargs": {
                                "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                                "trust_mark_specification": {"https://refeds.org/sirtfi": {}}
                            }
                        }
                    }
                }
            }
        )

        self.ta.server.subordinate[TRUST_MARK_ISSUER_ID] = {
            "jwks": self.tmi.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {TRUST_MARK_ISSUER_ID, IM_ID}

    def test_trust_mark_verifier(self):
        where_and_what = create_trust_chain_messages(self.tmi, self.ta)

        _trust_mark = create_trust_mark(entity_id=self.tmi.entity_id,
                                        keyjar=self.tmi.get_attribute('keyjar'),
                                        id=rndstr(),
                                        sub=self.rp.entity_id,
                                        lifetime=3600,
                                        reference='https://refeds.org/sirtfi')

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = self.rp.function.trust_mark_verifier(
                trust_mark=_trust_mark, trust_anchor=self.ta.entity_id)

        assert verified_trust_mark
