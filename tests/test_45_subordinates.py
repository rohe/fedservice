# AbstractFileSystem
import json
import os
import shutil

from idpyoidc.util import QPKey
import pytest

from tests import rm_dir_files
from tests.build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)

TA_ID = "https://trust_anchor.example.com"
RP_ID = "https://rp.example.com"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": {
            'class': 'idpyoidc.storage.abfile.AbstractFileSystem',
            'kwargs': {
                'fdir': full_path('subordinate')
            }
        },
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    RP_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        }
    }
}


class TestSubordinatePersistenceFileSystem(object):

    @pytest.fixture(autouse=True)
    def create_entities(self):
        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.rp = federation[RP_ID]

        _info = {
            "jwks": self.rp["federation_entity"].keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        _dir = full_path('subordinate')
        rm_dir_files(_dir)
        fname = os.path.join(_dir, QPKey().serialize(RP_ID))
        with open(fname, 'w') as f:
            f.write(json.dumps(_info))

    def test_list(self):
        _endpoint = self.ta.get_endpoint('list')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args
        assert _resp_args['response_msg'] == f'["{self.rp["federation_entity"].entity_id}"]'
