# AbstractFileSystem
import json

import pytest
from idpyoidc.util import QPKey

from fedservice.build_entity import FederationEntityBuilder
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity

TA_ID = "https://trust_anchor.example.com"
TA_ID2 = "https://2nd.trust_anchor.example.com"
LEAF_ID = "https://leaf.example.com"
INTERMEDIATE_ID = "https://intermediate.example.com"
TENNANT_ID = "https://example.org/tennant1"

# As long as it doesn't provide the Resolve endpoint it doesn't need
# services and functions.
# It must have the openid-federation and fetch endpoints. It may have the
# list and status endpoint. That's the case here.

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
del TA_ENDPOINTS["resolve"]


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class TestClient(object):

    @pytest.fixture(autouse=True)
    def create_entities(self):
        TA = FederationEntityBuilder(
            TA_ID,
            metadata={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_conf={"key_defs": KEYDEFS}
        )
        TA.add_endpoints(None,
                         args={
                             'subordinate': {
                                 'class': 'idpyoidc.storage.abfile.AbstractFileSystem',
                                 'kwargs': {
                                     'fdir': 'subordinate'
                                 }
                             }
                         },
                         **TA_ENDPOINTS)

        # Leaf

        ENT = FederationEntityBuilder(
            LEAF_ID,
            metadata={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_conf={"key_defs": KEYDEFS},
            authority_hints=[TA_ID]
        )
        ENT.add_services()
        ENT.add_functions()
        ENT.add_endpoints(None, **LEAF_ENDPOINT)

        self.ta = FederationEntity(**TA.conf)

        self.entity = FederationEntity(**ENT.conf)
        self.entity.function.trust_chain_collector.trust_anchors = {
            self.ta.entity_id: self.ta.keyjar.export_jwks()
        }
        # Create subordinate information and write it to the 'subordinate' directory
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
