import copy

from fedservice.combo import FederationCombo
import pytest
import requests
import responses

from fedservice.entity import FederationEntity
from fedservice.entity.client import FederationEntityClient
from fedservice.entity.client.entity_configuration import \
    EntityConfiguration as c_EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.trust_chain_collector import tree2chains
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.entity_configuration import EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.entity.server.list import List
from fedservice.node import Collection

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

INTERMEDIATE_CONFIG = {
    # "entity_id": TA_ID,
    "key_conf": {"key_defs": KEYDEFS},
    "federation_entity": {
        'class': FederationEntity,
        "kwargs": {
            "server": {
                'class': FederationEntityServer,
                'kwargs': {
                    "metadata": {},
                    "endpoint": {
                        "entity_configuration": {
                            "path": ".well-known/openid-federation",
                            "class": EntityConfiguration,
                            "kwargs": {}
                        },
                        "fetch": {
                            "path": "fetch",
                            "class": Fetch,
                            "kwargs": {}
                        },
                        "list": {
                            "path": "list",
                            "class": List,
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    }
}

TA_CONFIG = INTERMEDIATE_CONFIG.copy()
TA_CONFIG["entity_id"] = TA_ID
TA_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "organization_name": "The example cooperation",
    "homepage_uri": "https://www.example.com",
    "contacts": "operations@example.com"
}

IM_CONFIG = INTERMEDIATE_CONFIG.copy()
IM_CONFIG["entity_id"] = IM_ID
IM_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "authority_hints": [TA_ID],
    "organization_name": "The example cooperation",
    "homepage_uri": "https://www.example.com",
    "contacts": "ops@example.com"
}

LEAF_CONFIG = {
    # "entity_id": *_ID,
    "key_conf": {"key_defs": KEYDEFS},
    "federation_entity": {
        'class': FederationEntity,
        "kwargs": {
            "function": {
                'class': Collection,
                'kwargs': {
                    'functions': {
                        "trust_chain_collector": {
                            "class": TrustChainCollector,
                            "kwargs": {
                                # "trust_anchors": ANCHOR,
                                "allowed_delta": 600
                            }
                        },
                        'verifier': {
                            'class': TrustChainVerifier,
                            'kwargs': {}
                        },
                        'policy': {
                            'class': TrustChainPolicy,
                            'kwargs': {}
                        }
                    }
                }
            },
            "client": {
                'class': FederationEntityClient,
                'kwargs': {
                    "services": {
                        "entity_configuration": {
                            "class": c_EntityConfiguration,
                            "kwargs": {}
                        },
                        "entity_statement": {
                            "class": EntityStatement,
                            "kwargs": {}
                        }
                    }
                }
            },
            "server": {
                'class': FederationEntityServer,
                'kwargs': {
                    "metadata": {
                        # "authority_hints": [TA_ID],
                        # "organization_name": "The example",
                        # "homepage_uri": "https://www.example.com",
                        # "contacts": "app@rp.example.com"
                    },
                    "endpoint": {
                        "entity_configuration": {
                            "path": ".well-known/openid-federation",
                            "class": EntityConfiguration,
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    }
}

RP_CONFIG = copy.deepcopy(LEAF_CONFIG)
RP_CONFIG["entity_id"] = RP_ID
RP_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "authority_hints": [IM_ID],
    "organization_name": "The example",
    "homepage_uri": "https://www.example.com",
    "contacts": "app@rp.example.com"
}

OP_CONFIG = copy.deepcopy(LEAF_CONFIG)
OP_CONFIG["entity_id"] = OP_ID
OP_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "authority_hints": [TA_ID],
    "organization_name": "The example identity provider",
    "homepage_uri": "https://www.example.com",
    "contacts": "operations@op.example.com"
}


#              TA
#          +---|---+
#          |       |
#          IM      OP
#          |
#          RP

class TestComboCollect(object):
    @pytest.fixture(autouse=True)
    def setup(self):
        # TRUST ANCHOR
        self.ta = FederationCombo(TA_CONFIG, httpc=requests)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks_as_json()}

        # Intermediate
        self.im = FederationCombo(IM_CONFIG, httpc=requests)

        # Leaf RP
        _config = RP_CONFIG.copy()
        _config['federation_entity']['kwargs']['function']['kwargs'][
            'functions']['trust_chain_collector']['kwargs']['trust_anchors'] = ANCHOR
        self.rp = FederationCombo(_config)

        # Leaf OP
        _config = OP_CONFIG.copy()
        _config['federation_entity']['kwargs']['function']['kwargs'][
            'functions']['trust_chain_collector']['kwargs']['trust_anchors'] = ANCHOR
        self.op = FederationCombo(_config)

        _trust_anchor_federation_entity_server = self.ta['federation_entity'].server
        _trust_anchor_federation_entity_server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        _trust_anchor_federation_entity_server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        _im_federation_entity_server = self.im['federation_entity'].server
        _im_federation_entity_server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'authority_hints': [IM_ID]
        }

    def test_setup(self):
        assert self.ta
        assert self.ta['federation_entity'].server
        assert set(self.ta['federation_entity'].server.subordinate.keys()) == {OP_ID, IM_ID}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (leaf and TA) and 1 entity statement (TA about leaf
        # leaf = OP

        where_and_what = {}

        _endpoint = self.rp['federation_entity'].server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

        _endpoint = self.im['federation_entity'].server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

        _endpoint = self.im['federation_entity'].server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'iss': IM_ID, 'sub': RP_ID})
        where_and_what[_endpoint.full_path] = _endpoint.process_request(_req)["response"]

        _endpoint = self.ta['federation_entity'].server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

        _endpoint = self.ta['federation_entity'].server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'iss': TA_ID, 'sub': IM_ID})
        where_and_what[_endpoint.full_path] = _endpoint.process_request(_req)["response"]

        assert len(where_and_what) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _collector = self.op['federation_entity'].function.trust_chain_collector
            _tree, leaf_ec = _collector(RP_ID)

        assert _tree
        chains = tree2chains(_tree)
        assert len(chains) == 1
        assert len(chains[0]) == 2

        _verifier = self.op['federation_entity'].function.verifier
        chain_0 = chains[0]
        chain_0.append(leaf_ec)
        trust_chain = _verifier(chain_0)
        assert trust_chain

        _policy_applier = self.op['federation_entity'].function.policy
        _policy_applier(trust_chain, 'federation_entity')
        assert trust_chain.metadata
        assert set(trust_chain.metadata.keys()) == {'organization_name', 'homepage_uri', 'contacts'}
        assert trust_chain.metadata["contacts"] == 'app@rp.example.com'
