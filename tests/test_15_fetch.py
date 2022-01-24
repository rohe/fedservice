import os

from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar
import pytest

from fedservice.entity import FederationEntity
from fedservice.entity.fetch import Fetch
from fedservice.entity.list import List
from fedservice.metadata_api.fs2 import read_info

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')
ANCHOR = {'https://feide.no': read_info(os.path.join(ROOT_DIR, 'feide.no'), "feide.no", "jwks")}
ENTITY_ID = "https://op.ntnu.no"

SUB_KEYJAR = init_key_jar(key_defs=KEYSPEC)
SUBORDINATES = {
    "https://example.com": {
        "jwks": {"keys": SUB_KEYJAR.export_jwks()},
        "metadata_policy": {
            "openid_provider": {
                "organization_name": {"value": "NTNU"}
            }
        }
    }
}

CONFIG = {
    "entity_id": ENTITY_ID,
    "keys": {"uri_path": "static/fed_jwks.json",
             "private_path": os.path.join(ROOT_DIR, 'foodle.uninett.no',
                                          'foodle.uninett.no', 'jwks.json')},
    "endpoint": {
        "fetch": {
            "path": "fetch",
            "class": Fetch,
            "kwargs": {
                "client_authn_method": None,
                "subordinates": SUBORDINATES
            },
        },
        "list": {
            "path": "list",
            "class": List,
            "kwargs": {
                "client_authn_method": None,
                "subordinates": SUBORDINATES
            },
        }
    },
    "trusted_roots": ANCHOR,
    "authority_hints": ['https://ntnu.no'],
    "entity_type": 'federation_entity'
}


class Test(object):
    @pytest.fixture(autouse=True)
    def create_issuer(self):
        self.entity = FederationEntity(config=CONFIG)
        self.endpoint = self.entity.server_get('endpoint', 'fetch')

    def test_self(self):
        _context = self.endpoint.server_get("context")
        _res = self.endpoint.process_request({"iss": _context.entity_id})
        assert _res
        assert len(_res["response_args"]) == 3
        _info = self.endpoint.do_response(response_args=_res["response_args"],
                                          request={"iss": _context.entity_id})
        assert _info
        _jws = factory(_info["response"])
        _payload = _jws.jwt.payload()
        assert _payload["iss"] == _context.entity_id
        assert set(_payload.keys()) == {'sub', 'metadata', 'authority_hints',
                                        'jwks', 'iss', 'iat', 'exp'}

    def test_sub(self):
        _context = self.endpoint.server_get("context")
        _req = {
            "iss": _context.entity_id,
            "sub": "https://example.com"
        }
        _res = self.endpoint.process_request(_req)
        assert _res
        assert len(_res["response_args"]) == 3
        assert set(_res["response_args"].keys()) == {'jwks', 'metadata_policy', 'authority_hints'}
        _info = self.endpoint.do_response(response_args=_res["response_args"],
                                          request=_req)
        assert _info
        _jws = factory(_info["response"])
        _payload = _jws.jwt.payload()
        assert _payload["iss"] == _context.entity_id
        assert set(_payload.keys()) == {'sub', 'metadata_policy', 'authority_hints',
                                        'jwks', 'iss', 'iat', 'exp'}

        assert _payload["sub"] == "https://example.com"

    def test_metadata(self):
        metadata = self.entity.get_metadata()
        _ctx = self.entity.context
        iss = sub = _ctx.entity_id
        _statement = _ctx.create_entity_statement(
            metadata={_ctx.entity_type: metadata},
            iss=iss, sub=sub, authority_hints=_ctx.authority_hints,
            lifetime=_ctx.default_lifetime)

        _jws = factory(_statement)
        _payload = _jws.jwt.payload()
        assert _payload["iss"] == _ctx.entity_id
        assert set(_payload.keys()) == {'sub', 'metadata', 'authority_hints',
                                        'jwks', 'iss', 'iat', 'exp'}

        assert _payload["sub"] == "https://op.ntnu.no"

