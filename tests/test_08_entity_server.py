from idpyoidc.util import instantiate
import pytest

from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.entity_configuration import EntityConfiguration
from fedservice.entity.server.fetch import Fetch

OPPONENT_ID = "https://example.org"
TENNANT_ID = "https://example.org/tennant1"
ENTITY_ID = "https://entity.example.org"
ISSUER = "https://example.org/adm1"


class TestEntityServer(object):
    @pytest.fixture(autouse=True)
    def server_setup(self):
        conf = {
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
                }
            }
        }

        self.entity = instantiate(FederationEntityServer, config=conf, entity_id=ENTITY_ID)

    def test_entity_configuration(self):
        _endpoint = self.entity.get_endpoint('entity_configuration')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args

        # _res = _serv.get_request_parameters(request_args={"entity_id": OPPONENT_ID})
        # assert _res == {
        #     'method': 'GET',
        #     'url': 'https://example.org/.well-known/openid-federation'
        # }
        # _res = _serv.get_request_parameters(request_args={"entity_id": TENNANT_ID}, tenant=True)
        # assert _res == {
        #     'method': 'GET',
        #     'url': 'https://example.org/tennant1/.well-known/openid-federation'
        # }


    # def test_fetch(self):
    #     _serv = self.entity.get_service('entity_statement')
    #     _res = _serv.get_request_parameters(fetch_endpoint=f"{OPPONENT_ID}/fetch")
    #     assert _res == {
    #         'method': 'GET',
    #         'url': 'https://example.org/fetch'
    #     }
    #     _res = _serv.get_request_parameters(fetch_endpoint=f"{OPPONENT_ID}/fetch", issuer=ENTITY_ID)
    #     assert _res == {
    #         'method': 'GET',
    #         'url': 'https://example.org/fetch?iss=https%3A%2F%2Fentity.example.org'
    #     }
    #
    #     _res = _serv.get_request_parameters(fetch_endpoint=f"{OPPONENT_ID}/fetch", issuer=ISSUER,
    #                                         subject=ENTITY_ID)
    #     assert _res == {
    #         'method': 'GET',
    #         'url': 'https://example.org/fetch?iss=https%3A%2F%2Fexample.org%2Fadm1&sub=https%3A%2F'
    #                '%2Fentity.example.org'
    #     }
