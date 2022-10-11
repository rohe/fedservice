from cryptojwt.jws.jws import factory
from idpyoidc.util import instantiate
import pytest

from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity

# Trust Anchor
from tests.build_entity import FederationEntityBuilder

TA_ID = "https://trust_anchor.example.com"
LEAF_ID = "https://leaf.example.com"
INTERMEDIATE_ID = "https://intermediate.example.com"

TA = FederationEntityBuilder(
    TA_ID,
    metadata={
        "organization_name": "The example federation operator",
        "homepage_uri": "https://ta.example.com",
        "contacts": "operations@ta.example.com"
    }
)
TA.add_endpoints()

# Leaf

ENT = FederationEntityBuilder(
    LEAF_ID,
    metadata={
        "organization_name": "The leaf operator",
        "homepage_uri": "https://leaf.example.com",
        "contacts": "operations@leaf.example.com"
    }
)
ENT.add_services()
ENT.add_functions()
ENT.add_endpoints(**LEAF_ENDPOINT)

# Intermediate

INT = FederationEntityBuilder(
    INTERMEDIATE_ID,
    metadata={
        "organization_name": "The leaf operator",
        "homepage_uri": "https://leaf.example.com",
        "contacts": "operations@leaf.example.com"
    }
)
INT.add_services()
INT.add_functions()
INT.add_endpoints()

# Simple chain setup leaf->intermediate->trust anchor


class TestServer():
    @pytest.fixture(autouse=True)
    def create_entities(self):
        self.ta = FederationEntity(**TA.conf)

        self.intermediate = FederationEntity(**ENT.conf)
        self.intermediate.function.trust_chain_collector.trust_anchors = {
            self.ta.entity_id: self.ta.keyjar.export_jwks()
        }
        self.intermediate.server.endpoint_context.authority_hints = [self.ta.entity_id]

        self.entity = FederationEntity(**ENT.conf)
        self.entity.function.trust_chain_collector.trust_anchors = {
            self.ta.entity_id: self.ta.keyjar.export_jwks()
        }
        self.entity.server.endpoint_context.authority_hints = [self.intermediate.entity_id]

        self.intermediate.server.subordinate = {
            self.entity.entity_id: {
                "jwks": self.entity.keyjar.export_jwks(),
                'authority_hints': [TA_ID]
            }
        }

        self.ta.server.subordinate = {
            self.intermediate.entity_id: {
                "jwks": self.intermediate.keyjar.export_jwks(),
                'authority_hints': [TA_ID]
            }
        }

    def test_entity_configuration(self):
        _endpoint = self.entity.get_endpoint('entity_configuration')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert set(_resp_args.keys()) == {'response'}
        _jws = factory(_resp_args["response"])
        payload = _jws.jwt.payload()
        assert payload['iss'] == self.entity.entity_id
        assert payload['sub'] == self.entity.entity_id
        assert set(payload['metadata']['federation_entity'].keys()) == {'organization_name',
                                                                        'homepage_uri',
                                                                        'contacts'}
