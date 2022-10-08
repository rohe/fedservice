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

