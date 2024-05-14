import pytest
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_entity

LEAF_ID = "https://leaf.example.org"
TA_ID = "https://ta.example.org"
TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]


class TestSelfSignedTrustMark(object):

    @pytest.fixture(autouse=True)
    def setup(self):
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

        self.leaf = make_federation_entity(
            LEAF_ID,
            preference={
                "organization_name": "A leaf",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            self_signed_trust_mark_entity={
                "class": "fedservice.trust_mark_entity.entity.SelfSignedTrustMarkEntity",
                "kwargs": {
                    "trust_mark_specification": {
                        "https://refeds.org/category/personalized/op": {}
                    }
                }
            }
        )
