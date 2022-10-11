import pytest

from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.client.entity_configuration import EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement
# Trust Anchor
from tests.build_entity import FederationEntityBuilder

# OPPONENT_ID = "https://example.org"
# TENNANT_ID = "https://example.org/tennant1"
# ENTITY_ID = "https://entity.example.org"
# ISSUER = "https://example.org/adm1"
#
# KEYDEFS = [
#     {"type": "RSA", "key": "", "use": ["sig"]},
#     {"type": "EC", "crv": "P-256", "use": ["sig"]},
# ]
#
# KEYJAR = init_key_jar(key_defs=KEYDEFS)

TA_ID = "https://trust_anchor.example.com"
LEAF_ID = "https://leaf.example.com"
TENNANT_ID = "https://example.org/tennant1"

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


class TestClient():
    @pytest.fixture(autouse=True)
    def create_issuer(self):
        self.ta = FederationEntity(**TA.conf)

        self.entity = FederationEntity(**ENT.conf)
        self.entity.function.trust_chain_collector.trust_anchors = {
            self.ta.entity_id: self.ta.keyjar.export_jwks()
        }
        self.entity.server.endpoint_context.authority_hints = [self.ta.entity_id]

    def test_entity_configuration_request(self):
        _serv = self.entity.get_service('entity_configuration')
        _res = _serv.get_request_parameters(request_args={"entity_id": self.ta.entity_id})
        assert _res == {
            'method': 'GET',
            'url': 'https://trust_anchor.example.com/.well-known/openid-federation'
        }
        _res = _serv.get_request_parameters(request_args={"entity_id": TENNANT_ID}, tenant=True)
        assert _res == {
            'method': 'GET',
            'url': 'https://example.org/tennant1/.well-known/openid-federation'
        }

    def test_entity_statement_request(self):
        conf = {
            "services": {
                "entity_configuration": {
                    "class": EntityConfiguration,
                    "kwargs": {}
                },
                "entity_statement": {
                    "class": EntityStatement,
                    "kwargs": {}
                }
            }
        }

        _serv = self.entity.get_service('entity_statement')
        _res = _serv.get_request_parameters(fetch_endpoint=f"{self.ta.entity_id}/fetch")
        assert _res == {
            'method': 'GET',
            'url': 'https://trust_anchor.example.com/fetch'
        }
        _res = _serv.get_request_parameters(fetch_endpoint=f"{self.ta.entity_id}/fetch",
                                            issuer=self.ta.entity_id)
        assert _res == {
            'method': 'GET',
            'url':
                'https://trust_anchor.example.com/fetch?iss=https%3A%2F%2Ftrust_anchor.example.com'
        }

        _res = _serv.get_request_parameters(fetch_endpoint=f"{self.ta.entity_id}/fetch",
                                            issuer=self.ta.entity_id,
                                            subject=self.entity.entity_id)
        assert _res == {
            'method': 'GET',
            'url': 'https://trust_anchor.example.com/fetch?iss=https%3A%2F%2Ftrust_anchor.example'
                   '.com&sub=https%3A%2F%2Fleaf.example.com'
        }

    def test_resolve_request(self):
        _serv = self.entity.get_service('resolve')
        _res = _serv.get_request_parameters(
            request_args={"sub": self.entity.entity_id, "anchor": self.ta.entity_id},
            endpoint=f'{self.ta.entity_id}/.well-known/openid-federation')

        assert _res == {
            'method': 'GET',
            'url': 'https://trust_anchor.example.com/.well-known/openid-federation?sub=https%3A'
                   '%2F%2Fleaf.example.com&anchor=https%3A%2F%2Ftrust_anchor.example.com'

        }
