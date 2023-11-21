from cryptojwt.jws.jws import factory
import pytest
import responses

from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity.function.trust_mark_verifier import TrustMarkVerifier
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.message import EntityStatement
from fedservice.message import ResolveResponse
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages

TA1_ID = "https://trust_anchor.example.com"
TA2_ID = "https://2nd.trust_anchor.example.com"
LEAF_ID = "https://leaf.example.com"
INTERMEDIATE_ID = "https://intermediate.example.com"
TENNANT_ID = "https://example.org/tennant1"

# As long as it doesn't provide the Resolve endpoint it doesn't need
# services and functions.
# It must have the openid-federation and fetch endpoints. It may have the
# list and status endpoint. That's the case here.

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class TestClient(object):

    @pytest.fixture(autouse=True)
    def create_entities(self):
        self.ta = make_federation_entity(
            entity_id=TA1_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            endpoints=TA_ENDPOINTS
        )

        # Leaf

        self.entity = make_federation_entity(
            entity_id=LEAF_ID,
            preference={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            authority_hints=[TA1_ID],
            endpoints=["entity_configuration"]
        )

        self.entity.function.trust_chain_collector.trust_anchors = {
            self.ta.entity_id: self.ta.keyjar.export_jwks()
        }

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


class TestServer():

    @pytest.fixture(autouse=True)
    def create_entities(self):
        # Simple chain setup leaf->intermediate->trust anchor
        self.ta = make_federation_entity(
            TA1_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            endpoints=TA_ENDPOINTS,
            functions=[],
            services=[]
        )

        # Intermediate

        self.intermediate = make_federation_entity(
            INTERMEDIATE_ID,
            preference={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            authority_hints=[TA1_ID],
            endpoints=["entity_configuration", "fetch", "list", "resolve"],
            trust_anchors={TA1_ID: self.ta.keyjar.export_jwks()}
        )

        # Leaf

        self.leaf = make_federation_entity(
            LEAF_ID,
            preference={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            authority_hints=[INTERMEDIATE_ID],
            endpoints=["entity_configuration"],
            trust_anchors={TA1_ID: self.ta.keyjar.export_jwks()}
        )

        self.intermediate.server.subordinate = {
            self.leaf.entity_id: {
                "jwks": self.leaf.keyjar.export_jwks(),
                'authority_hints': [INTERMEDIATE_ID]
            }
        }

        self.ta.server.subordinate = {
            self.intermediate.entity_id: {
                "jwks": self.intermediate.keyjar.export_jwks(),
                'authority_hints': [TA1_ID],
                "registration_info": {
                    "intermediate": True,
                    "entity_types": ["federation_entity"]
                }
            }
        }

    def test_entity_setup(self):
        assert self.leaf.function
        assert isinstance(self.leaf.function.trust_chain_collector, TrustChainCollector)
        assert isinstance(self.leaf.function.trust_mark_verifier, TrustMarkVerifier)
        assert isinstance(self.leaf.function.policy, TrustChainPolicy)
        assert isinstance(self.leaf.function.verifier, TrustChainVerifier)

        _client = self.leaf.client
        assert _client.get_service_names() == {'entity_configuration',
                                               'entity_statement',
                                               'list',
                                               'resolve'}

        assert _client.get_service('entity_configuration').service_name == 'entity_configuration'
        assert _client.get_service('entity_statement').service_name == 'entity_statement'

        assert set(self.leaf.server.endpoint.keys()) == {'entity_configuration'}

    def test_ta_setup(self):
        assert self.ta.function is None
        assert self.ta.client is None

        assert set(self.ta.server.endpoint.keys()) == {'entity_configuration', 'fetch', 'list'}

    def test_entity_configuration(self):
        _endpoint = self.leaf.get_endpoint('entity_configuration')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert set(_resp_args.keys()) == {'response'}
        entity_configuration = verify_self_signed_signature(_resp_args['response'])
        assert entity_configuration['iss'] == self.leaf.entity_id
        assert entity_configuration['sub'] == self.leaf.entity_id
        assert set(entity_configuration['metadata']['federation_entity'].keys()) == {
            'organization_name', 'homepage_uri', 'contacts', 'jwks'}

    def test_fetch(self):
        _endpoint = self.ta.get_endpoint('fetch')
        _req = _endpoint.parse_request({"sub": self.intermediate.entity_id})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args

        _jws = factory(_resp_args["response_msg"])
        payload = _jws.jwt.payload()
        entity_statement = EntityStatement(**payload)
        entity_statement.verify()
        assert entity_statement['iss'] == self.ta.entity_id
        assert entity_statement['sub'] == self.intermediate.entity_id
        assert entity_statement['authority_hints'] == [self.ta.entity_id]

    def test_list(self):
        _endpoint = self.ta.get_endpoint('list')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args
        assert _resp_args['response_msg'] == f'["{self.intermediate.entity_id}"]'

    def test_resolve(self):
        _msgs = create_trust_chain_messages(self.leaf, self.intermediate, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _endpoint = self.intermediate.get_endpoint('resolve')
            _req = _endpoint.parse_request({
                "sub": self.leaf.entity_id,
                "anchor": self.ta.entity_id
            })
            _resp_args = _endpoint.process_request(_req)

        assert _resp_args
        _jws = factory(_resp_args["response_args"])
        payload = _jws.jwt.payload()
        entity_statement = ResolveResponse(**payload)
        entity_statement.verify()


class TestFunction:

    @pytest.fixture(autouse=True)
    def create_entities(self):
        # Two chains leaf->intermediate->trust_anchor_1 and leaf->trust_anchor_2
        #       TA1     TA2_ID
        #       |      |
        #      IM      |
        #       \      |
        #        +--- LEAF

        # trust anchor 1 and 2
        self.ta1 = make_federation_entity(
            TA1_ID,
            preference={
                "organization_name": "The first federation operator",
                "homepage_uri": "https://ta1.example.com",
                "contacts": "operations@ta1.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            endpoints=TA_ENDPOINTS
        )

        self.ta2 = make_federation_entity(
            TA2_ID,
            preference={
                "organization_name": "The second federation operator",
                "homepage_uri": "https://ta2.example.com",
                "contacts": "operations@ta2.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            endpoints=TA_ENDPOINTS
        )

        # Intermediate

        self.intermediate = make_federation_entity(
            INTERMEDIATE_ID,
            preference={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            authority_hints=[TA1_ID],
            endpoints=["entity_configuration", "fetch", "list"],
            trust_anchors={self.ta1.entity_id: self.ta1.keyjar.export_jwks()}
        )

        # Leaf

        self.leaf = make_federation_entity(
            LEAF_ID,
            preference={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_config={"key_defs": KEYDEFS},
            authority_hints=[INTERMEDIATE_ID, TA2_ID],
            endpoints=["entity_configuration"],
            trust_anchors={
                self.ta2.entity_id: self.ta2.keyjar.export_jwks(),
                self.ta1.entity_id: self.ta1.keyjar.export_jwks()
            }
        )

        # The first chain

        self.ta1.server.subordinate = {
            self.intermediate.entity_id: {
                "jwks": self.intermediate.keyjar.export_jwks(),
                'authority_hints': [TA1_ID]
            }
        }
        self.intermediate.server.subordinate = {
            self.leaf.entity_id: {
                "jwks": self.leaf.keyjar.export_jwks(),
                'authority_hints': [INTERMEDIATE_ID]
            }
        }

        # the second chain

        self.ta2.server.subordinate = {
            self.leaf.entity_id: {
                "jwks": self.leaf.keyjar.export_jwks(),
                'authority_hints': [TA2_ID]
            }
        }

    def test_trust_chains_to_intermediate(self):
        _federation_entity = self.intermediate

        _msgs = create_trust_chain_messages(self.leaf, self.intermediate, self.ta1)
        _msgs.update(create_trust_chain_messages(self.leaf, self.ta2))

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _chains, _entity_conf = collect_trust_chains(_federation_entity, self.leaf.entity_id)

        _jws = factory(_entity_conf)
        _unver_entity_conf = _jws.jwt.payload()
        assert _unver_entity_conf['iss'] == self.leaf.entity_id
        assert _unver_entity_conf['sub'] == self.leaf.entity_id

        assert len(_chains) == 2

        # Intermediate doesn't have TA2_ID as trust anchor
        _trust_chains = verify_trust_chains(_federation_entity, _chains, _entity_conf)
        assert len(_trust_chains) == 1

    def test_trust_chains_to_leaf(self):
        _federation_entity = self.leaf

        _msgs = create_trust_chain_messages(self.leaf, self.intermediate, self.ta1)
        _msgs.update(create_trust_chain_messages(self.leaf, self.ta2))

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _chains, _entity_conf = collect_trust_chains(_federation_entity, self.leaf.entity_id)

        _jws = factory(_entity_conf)
        _unver_entity_conf = _jws.jwt.payload()
        assert _unver_entity_conf['iss'] == self.leaf.entity_id
        assert _unver_entity_conf['sub'] == self.leaf.entity_id

        assert len(_chains) == 2

        # Leaf trusts both trust anchors
        _trust_chains = verify_trust_chains(_federation_entity, _chains, _entity_conf)
        assert len(_trust_chains) == 2

    def test_upstream_context_attribute(self):
        assert self.leaf.client.upstream_get('context_attribute', 'entity_id') == LEAF_ID
        assert self.leaf.function.upstream_get('context_attribute', 'entity_id') == LEAF_ID
        assert self.leaf.function.policy.upstream_get('context_attribute', 'entity_id') == LEAF_ID
        assert self.leaf.server.upstream_get('context_attribute', 'entity_id') == LEAF_ID

    def test_upstream_attribute(self):
        assert self.leaf.client.upstream_get('attribute', 'keyjar') == self.leaf.keyjar
        assert self.leaf.function.upstream_get('attribute', 'keyjar') == self.leaf.keyjar
        assert self.leaf.function.policy.upstream_get('attribute', 'keyjar') == self.leaf.keyjar
        assert self.leaf.server.upstream_get('attribute', 'keyjar') == self.leaf.keyjar

    def test_trust_anchors_attribute(self):
        assert set(self.leaf.trust_anchors.keys()) == {'https://trust_anchor.example.com',
                                                       'https://2nd.trust_anchor.example.com'}
