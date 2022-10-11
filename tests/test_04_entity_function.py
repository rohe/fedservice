import pytest

from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.trust_mark_verifier import TrustMarkVerifier
from fedservice.entity.function.verifier import TrustChainVerifier
from tests.build_entity import FederationEntityBuilder

# Trust Anchor
TA_ID = "https://trust_anchor.example.com"
LEAF_ID = "https://leaf.example.com"

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


class TestFunction():
    @pytest.fixture(autouse=True)
    def create_issuer(self):
        self.ta = FederationEntity(**TA.conf)

        self.entity = FederationEntity(**ENT.conf)
        self.entity.function.trust_chain_collector.trust_anchors = {
            self.ta.entity_id: self.ta.keyjar.export_jwks()
        }
        self.entity.server.endpoint_context.authority_hints = [self.ta.entity_id]

        self.ta.server.subordinate = {
            self.entity.entity_id: {
                "jwks": self.entity.keyjar.export_jwks(),
                'authority_hints': [TA_ID]
            }
        }

    def test_setup(self):
        assert self.entity.function
        assert isinstance(self.entity.function.trust_chain_collector, TrustChainCollector)
        assert isinstance(self.entity.function.trust_mark_verifier, TrustMarkVerifier)
        assert isinstance(self.entity.function.policy, TrustChainPolicy)
        assert isinstance(self.entity.function.verifier, TrustChainVerifier)

        _client = self.entity.client
        assert set(_client.get_service_names()) == {'entity_configuration',
                                                    'entity_statement',
                                                    'trust_mark_status'}

        assert _client.get_service('entity_configuration').service_name == 'entity_configuration'
        assert _client.get_service('entity_statement').service_name == 'entity_statement'
        assert _client.get_service('trust_mark_status').service_name == 'trust_mark_status'

        assert set(self.entity.server.endpoint.keys()) == {'entity_configuration'}

    def test_create_entity_statement(self):
        pass
