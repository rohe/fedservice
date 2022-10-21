import json
import os

from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar
from idpyoidc.server.util import execute
import pytest

from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.client import FederationEntityClient
from fedservice.entity.client.entity_configuration import \
    EntityConfiguration as c_EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement
from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.entity_configuration import \
    EntityConfiguration as s_EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.entity.server.list import List
from tests.build_entity import FederationEntityBuilder

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

SUB_KEYJAR = init_key_jar(key_defs=KEYDEFS)
BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()
ANCHOR = {'https://feide.no': json.loads(jwks)}

OPPONENT_ID = "https://example.org"
TENNANT_ID = "https://example.org/tennant1"
ENTITY_ID = "https://entity.example.org"
CHILD_ID = "https://op.example.com"
ISSUER = "https://example.org/adm1"


class TestFederationEntity(object):

    @pytest.fixture(autouse=True)
    def server_setup(self):
        ENT = FederationEntityBuilder(
            ENTITY_ID,
            metadata={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_conf={"uri_path": "static/fed_jwks.json", "key_defs": KEYDEFS}
        )
        ENT.add_services()
        ENT.add_functions()
        ENT.add_endpoints(metadata={"authority_hints": ['https://ntnu.no']})
        ENT.set_attr(
            'server',
            {
                "subordinate": {
                    'https://op.example.com': {
                        "jwks": {"keys": SUB_KEYJAR.export_jwks()},
                        "metadata_policy": {
                            "openid_provider": {
                                "organization_name": {"value": "NTNU"}
                            }
                        }
                    }
                }
            }
        )

        self.entity = FederationEntity(**ENT.conf)

    def test_client(self):
        assert self.entity

        _serv = self.entity.client.get_service('entity_configuration')
        _res = _serv.get_request_parameters(request_args={"entity_id": OPPONENT_ID})
        assert _res == {
            'method': 'GET',
            'url': 'https://example.org/.well-known/openid-federation'
        }
        _res = _serv.get_request_parameters(request_args={"entity_id": TENNANT_ID}, tenant=True)
        assert _res == {
            'method': 'GET',
            'url': 'https://example.org/tennant1/.well-known/openid-federation'
        }

    def test_server(self):
        _endpoint = self.entity.server.get_endpoint('entity_configuration')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        _jwt = factory(_resp_args['response'])
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'iat',
                                       'metadata', 'iss', 'authority_hints'}
        assert payload["iss"] == payload["sub"]
        assert set(payload['metadata'].keys()) == {'federation_entity'}
        # Full set of endpoints
        for i in payload['metadata']['federation_entity'].keys():
            assert i in ('organization_name', 'homepage_uri', 'contacts',
                         'federation_fetch_endpoint',
                         'federation_list_endpoint',
                         'federation_resolve_endpoint')

    def test_fetch(self):
        _endpoint = self.entity.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'iss': ENTITY_ID, 'sub': CHILD_ID})
        _resp_args = _endpoint.process_request(_req)
        _jwt = factory(_resp_args['response'])
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'iat',
                                       'metadata_policy', 'iss', 'authority_hints'}
        assert payload["iss"] == ENTITY_ID
        assert payload["sub"] == CHILD_ID
        assert set(payload['metadata_policy'].keys()) == {'openid_provider'}
        assert set(payload['metadata_policy']['openid_provider'].keys()) == {'organization_name'}

    def test_list(self):
        _endpoint = self.entity.server.get_endpoint('list')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args['response'] == [CHILD_ID]
