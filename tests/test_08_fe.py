import json
import os

from idpyoidc.server.util import execute
import pytest

from fedservice.entity import FederationEntity
from fedservice.entity import client
from fedservice.entity.client import FederationEntityClient
from fedservice.entity.client.entity_configuration import EntityConfiguration as c_EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement
from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.entity_configuration import EntityConfiguration as s_EntityConfiguration
from fedservice.entity.server.fetch import Fetch

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()
ANCHOR = {'https://feide.no': json.loads(jwks)}

ENTITY_ID = "https://example.com/"
OPPONENT_ID = "https://example.org"


class TestEntityServer(object):
    @pytest.fixture(autouse=True)
    def server_setup(self):
        config = {
            'class': FederationEntity,
            "kwargs": {
                "trusted_roots": ANCHOR,
                "authority_hints": ['https://ntnu.no'],
                "organization_name": "The example cooperation",
                "homepage_uri": "https://www.example.com",
                "contacts": "operations@example.com",
                "entity_id": ENTITY_ID,
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
                        "endpoint": {
                            "entity_configuration": {
                                "path": ".well-known/openid-federation",
                                "class": s_EntityConfiguration,
                                "kwargs": {}
                            },
                            "fetch": {
                                "path": "fetch",
                                "class": Fetch,
                                "kwargs": {}
                            }
                        }
                    }
                }
            }
        }

        self.entity = execute(config)

    def test(self):
        assert self.entity

# class ABC():
#     def __init__(self, config=None):
#         self.config = get_configuration(config)
#
#         _tools = {k: v for k, v in self.config.conf.items() if
#                   k in ENTITY_TYPE2METADATA_CLASS.keys()}
#         self.tool = {entity_type: instantiate(args['class'], config=args["kwargs"]) for
#                      entity_type, args in _tools.items()}
#
#         self.config.conf = {k: v for k, v in self.config.conf.items() if
#                             k not in ENTITY_TYPE2METADATA_CLASS.keys()}
#
#         self.endpoint = {}
#         for _key, _item in self.tool.items():
#             for _attr, _val in _item.endpoint.items():
#                 self.endpoint[_attr] = _val
#
#         self.service = {}
#         for _key, _item in self.tool.items():
#             for _attr, _val in _item.service.items():
#                 self.service[_attr] = _val
#
#
# def test_base():
#     entity = ABC(CONFIG)
#     assert entity
#     _res = entity.service['entity_configuration'].construct_request(entity_id=OPPONENT_ID)
#     assert _res
#     _res = entity.service['entity_configuration'].get_request_parameters(
#         request_args={"entity_id": OPPONENT_ID}, method="GET")
#     assert _res
