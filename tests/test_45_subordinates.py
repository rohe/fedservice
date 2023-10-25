# AbstractFileSystem
import json

import pytest
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.util import QPKey

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_entity

TA_ID = "https://trust_anchor.example.com"
TA_ID2 = "https://2nd.trust_anchor.example.com"
LEAF_ID = "https://leaf.example.com"
INTERMEDIATE_ID = "https://intermediate.example.com"
TENNANT_ID = "https://example.org/tennant1"

# As long as it doesn't provide the Resolve endpoint it doesn't need
# services and functions.
# It must have the openid-federation and fetch endpoints. It may have the
# list and status endpoint. That's the case here.

TA_ENDPOINTS = ["entity_configuration", "fetch", "list"]


class TestClient(object):

    @pytest.fixture(autouse=True)
    def create_entities(self):
        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=TA_ENDPOINTS,
            item_args={
                "endpoint": {
                    'subordinate': {
                        'class': 'idpyoidc.storage.abfile.AbstractFileSystem',
                        'kwargs': {
                            'fdir': 'subordinate'
                        }
                    }
                }
            }
        )

        # Leaf

        self.entity = make_federation_entity(
            LEAF_ID,
            preference={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors={self.ta.entity_id: self.ta.keyjar.export_jwks()}
        )

        _info = {
            "jwks": self.entity.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        fname = f'subordinate/{QPKey().serialize(LEAF_ID)}'
        with open(fname, 'w') as f:
            f.write(json.dumps(_info))

    def test_list(self):
        _endpoint = self.ta.get_endpoint('list')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args
        assert _resp_args['response_msg'] == f'["{self.entity.entity_id}"]'
