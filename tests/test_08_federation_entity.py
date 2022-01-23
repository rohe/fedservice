import os

from cryptojwt.jws.jws import factory
import pytest

from fedservice.entity import FederationEntity
from fedservice.entity.fetch import Fetch

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))

ENTITY_ID = "https://example.com/"


class TestNonLeafEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "httpc_params": {"verify": False, "timeout": 1},
            "federation": {
                "entity_id": ENTITY_ID,
                "endpoint": {
                    "fetch": {
                        "path": "fetch",
                        "class": Fetch,
                        "kwargs": {"client_authn_method": None},
                    }
                },
                "keys": {"uri_path": "static/fed_jwks.json", "key_defs": KEYDEFS},
                'authority_hints': os.path.join(BASEDIR,
                                                'base_data/op.ntnu.no/op.ntnu.no/authority.json'),
                'trusted_roots': os.path.join(BASEDIR, 'trusted_roots.json'),
                'priority': [],
                'entity_type': 'federation_entity',
                "name": "Example Entity",
                "contacts": "operations@example.com"
            }
        }
        server = FederationEntity(config=conf.get("federation"), entity_id=ENTITY_ID, cwd=BASEDIR)
        self.endpoint = server.server_get("endpoint", "fetch")

    def test_fetch(self):
        args = self.endpoint.process_request({"iss": ENTITY_ID})
        msg = self.endpoint.do_response(response_args=args["response_args"],
                                        request={"iss": ENTITY_ID})
        _res = factory(msg["response"])
        assert _res
        _payload = _res.jwt.payload()
        assert "metadata" in _payload
        _metadata = _payload["metadata"]
        assert "federation_entity" in _metadata
        _entity = _metadata["federation_entity"]
        assert "name" in _entity
