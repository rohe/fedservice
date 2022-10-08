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

TA_CONFIG = {
    "entity_id": TA_ID,
    "key_conf": {"key_defs": KEYDEFS},
    "federation_entity": {
        'class': FederationEntity,
        "kwargs": {
            "metadata": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            "server": {
                'class': FederationEntityServer,
                'kwargs': {
                    "metadata": {
                        "organization_name": "The example cooperation",
                        "homepage_uri": "https://www.example.com",
                        "contacts": "operations@example.com"
                    },
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

RP_CONFIG = {
    "entity_id": RP_ID,
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
                        "authority_hints": [TA_ID],
                        "organization_name": "The example",
                        "homepage_uri": "https://www.example.com",
                        "contacts": "app@rp.example.com"
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

OP_CONFIG = {
    "entity_id": OP_ID,
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
                        "authority_hints": [TA_ID],
                        "organization_name": "The example identity provider",
                        "homepage_uri": "https://www.example.com",
                        "contacts": "operations@op.example.com"
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


class TestComboCollect(object):
    @pytest.fixture(autouse=True)
    def setup(self):
        self.ta = FederationCombo(TA_CONFIG, httpc=requests)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks_as_json()}

        _config = RP_CONFIG.copy()
        _config['federation_entity']['kwargs']['function']['kwargs'][
            'functions']['trust_chain_collector']['kwargs']['trust_anchors'] = ANCHOR
        self.rp = FederationCombo(_config)

        _config = OP_CONFIG.copy()
        _config['federation_entity']['kwargs']['function']['kwargs'][
            'functions']['trust_chain_collector']['kwargs']['trust_anchors'] = ANCHOR
        self.op = FederationCombo(_config)

        _trust_anchor_federation_entity_server = self.ta['federation_entity'].server
        _trust_anchor_federation_entity_server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        _trust_anchor_federation_entity_server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

    def test_setup(self):
        assert self.ta
        assert self.ta['federation_entity'].server
        assert set(self.ta['federation_entity'].server.subordinate.keys()) == {OP_ID, RP_ID}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (leaf and TA) and 1 entity statement (TA about leaf
        # leaf = OP

        where_and_what = {}

        _endpoint = self.op['federation_entity'].server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

        _endpoint = self.ta['federation_entity'].server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

        _endpoint = self.ta['federation_entity'].server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'iss': TA_ID, 'sub': OP_ID})
        where_and_what[_endpoint.full_path] = _endpoint.process_request(_req)["response"]

        assert len(where_and_what) == 3

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _collector = self.rp['federation_entity'].function.trust_chain_collector
            _tree, leaf_ec = _collector(OP_ID)

        assert _tree
        chains = tree2chains(_tree)
        assert len(chains) == 1

        _verifier = self.rp['federation_entity'].function.verifier
        chain_0 = chains[0]
        chain_0.append(leaf_ec)
        trust_chain = _verifier(chain_0)
        assert trust_chain

        _policy_applier = self.rp['federation_entity'].function.policy
        _policy_applier(trust_chain, 'federation_entity')
        assert trust_chain.metadata
        assert set(trust_chain.metadata.keys()) == {'organization_name', 'homepage_uri', 'contacts'}

# def test_get_entity_statement():
#     entity_id = 'https://foodle.uninett.no'
#     target = 'https://foodle.uninett.no'
#     collector = DummyCollector(trusted_roots=ANCHOR,
#                                httpd=Publisher(os.path.join(BASE_PATH, 'base_data')),
#                                root_dir=os.path.join(BASE_PATH, 'base_data'))
#     _jws = collector.get_entity_statement(api_endpoint='https://foodle.uninett.no/fed_api',
#                                           issuer=entity_id, subject=target)
#
#     msg = verify_self_signed_signature(_jws)
#     assert msg['iss'] == entity_id
#     assert msg['sub'] == target
#
#
# def test_tree2chains_1():
#     tree = {
#         "https://example.com/rp": (
#             'statement1', {
#                 "https://example.com/intermediate1": (
#                     'statement2', {
#                         "https://example.com/anchor": (
#                             "statement3", {})})})}
#
#     chains = tree2chains(tree)
#     assert len(chains) == 1
#     assert len(chains[0]) == 3
#     assert chains[0] == ["statement3", "statement2", "statement1"]
#
#
# def test_tree2chains_2():
#     tree = {
#         "https://example.com/rp": (
#             'statement1', {
#                 "https://example.com/intermediate1": (
#                     'statement2', {
#                         "https://example.com/anchor1": ("statement3", {}),
#                         "https://example.com/anchor2": ("statement4", {})
#                     })})}
#
#     chains = tree2chains(tree)
#     assert len(chains) == 2
#     assert chains[0] == ["statement3", "statement2", "statement1"]
#     assert chains[1] == ["statement4", "statement2", "statement1"]
#
#
# def test_tree2chains_3():
#     tree = {
#         "https://example.com/rp": (
#             'statement1', {
#                 "https://example.com/intermediate1": (
#                     'statement2', {
#                         "https://example.com/anchor1": ("statement3", {})
#                     }
#                 ),
#                 "https://example.com/intermediate2": (
#                     'statement5', {
#                         "https://example.com/anchor2": ("statement4", {})
#                     }
#                 )
#             })}
#
#     chains = tree2chains(tree)
#     assert len(chains) == 2
#     assert chains[0] == ["statement3", "statement2", "statement1"]
#     assert chains[1] == ["statement4", "statement5", "statement1"]
#
#
# def test_tree2chains_4():
#     tree = {
#         "https://example.com/rp": (
#             'statement1', {
#                 "https://example.com/intermediate1": (
#                     'statement2', {
#                         "https://example.com/anchor1": ("statement3", {})
#                     }
#                 ),
#                 "https://example.com/intermediate2": (
#                     'statement5', {
#                         "https://example.com/anchor1": ("statement3", {})
#                     }
#                 )
#             })}
#
#     chains = tree2chains(tree)
#     assert len(chains) == 2
#     assert chains[0] == ["statement3", "statement2", "statement1"]
#     assert chains[1] == ["statement3", "statement5", "statement1"]
#
#
# def test_tree2chains_5():
#     tree = {
#         "https://example.com/rp": (
#             'statement1', {
#                 "https://example.com/intermediate1": (
#                     'statement2', {
#                         "https://example.com/anchor1": ("statement3", {})
#                     }
#                 ),
#                 "https://example.com/anchor2": ("statement4", {})
#             })}
#
#     chains = tree2chains(tree)
#     assert len(chains) == 2
#     assert chains[0] == ["statement3", "statement2", "statement1"]
#     assert chains[1] == ["statement4", "statement1"]
#
#
# def test_collect_superiors():
#     # entity_id = 'https://feide.no'
#     entity_id = 'https://foodle.uninett.no'
#     target = 'https://foodle.uninett.no'
#     collector = DummyCollector(trusted_roots=ANCHOR,
#                                httpd=Publisher(os.path.join(BASE_PATH, 'base_data')),
#                                root_dir=os.path.join(BASE_PATH, 'base_data'))
#     entity_statement = collector.get_entity_statement(
#         api_endpoint='https://foodle.uninett.no/fed_api',
#         issuer=entity_id, subject=entity_id)
#     _config = verify_self_signed_signature(entity_statement)
#     assert _config
#
#     tree = collector.collect_superiors(_config['iss'], entity_statement)
#     node = {entity_id: (entity_statement, tree)}
#     chains = tree2chains(node)
#
#     assert len(chains) == 1  # only one chain
#     assert len(chains[0]) == 4  # And that chain contains 4 statements
#     _jws00 = factory(chains[0][0])
#     payload = _jws00.jwt.payload()
#     # The Federation Entity Statement will be first in line
#     assert payload["iss"] == 'https://feide.no'
#
#
# def entity_statement_with_x5c():
#     metadata = {
#         "application_type": "web",
#         "claims": [
#             "sub",
#             "name",
#             "email",
#             "picture"
#         ],
#         "id_token_signing_alg_values_supported": [
#             "RS256",
#             "RS512"
#         ],
#         "redirect_uris": [
#             "https://foodle.uninett.no/callback"
#         ],
#         "response_types": [
#             "code"
#         ]
#     }
#
#     iss = "https://example.com"
#     sub = iss
#
#     key_jar = build_keyjar(KEYSPEC, issuer_id=iss)
#     authority = ["https://ntnu.no"]
#
#     with open(os.path.join(BASE_PATH, "cert.pem")) as fp:
#         pems = fp.read()
#
#     _x5c_val = pems_to_x5c([pems])
#     _jws = create_entity_statement(iss, sub, key_jar, metadata=metadata, authority_hints=authority,
#                                    x5c=_x5c_val)
#     return _jws
#
#
# def test_get_self_signed_entity_statement():
#     sses = entity_statement_with_x5c()
#
#     collector = Collector(trust_anchors=ANCHOR, http_cli=requests.request,
#                           insecure=True)
#     collector.ssc_dir = "."
#
#     with responses.RequestsMock() as rsps:
#         rsps.add(rsps.GET, "https://foodle.uninett.no/.well-known/openid-federation",
#                  body=sses)
#         # Get the self-signed entity statement from a leaf
#         self_signed_statement = collector.get_configuration_information("https://foodle.uninett.no")
#
#     _jwt = factory(self_signed_statement)
#     assert _jwt
#
#     # this should work. Not interested in the value, just that it can be done.
#     msg = _jwt.jwt.payload()
#     x5c_to_pems(msg["x5c"])
#
#     # Same here
#     collector.store_ssc_cert(msg, "https://foodle.uninett.no")
#
#
# def test_collect_configuration():
#     collector = Collector(trust_anchors=ANCHOR, http_cli=requests.request,
#                           insecure=True)
#
#     with responses.RequestsMock() as rsps:
#         rsps.add(rsps.GET, "https://foodle.uninett.no/.well-known/openid-federation", status=404)
#         # Get the self-signed entity statement from a leaf
#         with pytest.raises(MissingPage):
#             collector.get_configuration_information("https://foodle.uninett.no")
