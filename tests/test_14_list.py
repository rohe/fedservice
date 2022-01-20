import os

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

CONFIG = {
    "entity_id": ENTITY_ID,
    "keys": {"uri_path": "static/fed_jwks.json",
             "private_path": os.path.join(ROOT_DIR, 'foodle.uninett.no',
                                          'foodle.uninett.no', 'jwks.json')},
    "endpoint": {
        "fetch": {
            "path": "fetch",
            "class": Fetch,
            "kwargs": {"client_authn_method": None},
        },
        "list": {
            "path": "list",
            "class": List,
            "kwargs": {
                "client_authn_method": None,
                "subordinates": {
                    "https://example.com": SUB_KEYJAR.export_jwks()
                }
            },
        }
    },
    "trusted_roots": ANCHOR,
    "authority_hints": ['https://ntnu.no'],
    "entity_type": 'trust_mark_issuer'
}


class TestSelfSigned(object):
    @pytest.fixture(autouse=True)
    def create_issuer(self):
        _intermediate = FederationEntity(config=CONFIG)
        self.endpoint = _intermediate.server_get('endpoint', 'list')

    def test_list(self):
        # Create the Signed JWT representing the Trust Mark
        _res = self.endpoint.process_request({})
        assert _res
        assert len(_res["response_args"]) == 1 # a list with one object
