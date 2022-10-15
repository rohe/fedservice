import copy
import os

import pytest
from fedservice.combo import Combo

from fedservice.defaults import FEDERATION_ENTITY_FUNCTIONS
from fedservice.defaults import FEDERATION_ENTITY_SERVICES
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.client import FederationEntityClient
from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.status import TrustMarkStatus
from fedservice.message import TrustMark
from fedservice.fetch_entity_statement.fs2 import read_info
from fedservice.node import Collection
from fedservice.trust_mark_issuer import TrustMarkIssuer

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')
ANCHOR = {'https://feide.no': read_info(os.path.join(ROOT_DIR, 'feide.no'), "feide.no", "jwks")}

CONF = {
    'entity_id': "https://example.com/trust_mark_issuer",
    "key_conf": {"key_defs": KEYSPEC},
    'server': {
        'class': FederationEntityServer,
        'kwargs': {
            "endpoint": {
                "status": {
                    "path": "status",
                    "class": TrustMarkStatus,
                    "kwargs": {"client_authn_method": None},
                }
            }
        }
    }
}


class TestSignedTrustMark():

    @pytest.fixture(autouse=True)
    def create_entity(self):
        #
        self.tmi = TrustMarkIssuer(**copy.deepcopy(CONF))

    def test_create_trust_mark_self_signed(self):
        _trust_mark = self.tmi.self_signed_trust_mark(
            id='https://openid.net/certification',
            logo_uri=("http://openid.net/wordpress-content/uploads/2016/05/"
                      "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg")
        )
        # Unpack and verify the Trust Mark
        _mark = self.tmi.server.endpoint['status'].unpack_trust_mark(_trust_mark)

        assert isinstance(_mark, TrustMark)
        assert _mark["id"] == "https://openid.net/certification"
        assert _mark['iss'] == _mark['sub']
        assert _mark['iss'] == self.tmi.entity_id
        assert set(_mark.keys()) == {'iss', 'sub', 'iat', 'id', 'logo_uri'}

    def test_create_unpack_trust_3rd_party(self):
        _sub = "https://op.ntnu.no"
        self.tmi.trust_marks["https://refeds.org/sirtfi"] = {}
        _trust_mark = self.tmi.create_trust_mark("https://refeds.org/sirtfi", _sub)

        _mark = self.tmi.server.endpoint['status'].unpack_trust_mark(_trust_mark, _sub)

        assert isinstance(_mark, TrustMark)
        assert set(self.tmi.issued.keys()) == {"https://refeds.org/sirtfi"}
        assert set(self.tmi.issued['https://refeds.org/sirtfi'].keys()) == {_sub}


TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"

CONFIG = {
    'entity_id': "https://example.com/trust_mark_issuer",
    "key_conf": {"key_defs": KEYSPEC},
    "federation_entity": {
        'class': FederationEntity,
        "function": {
            'class': Collection,
            'kwargs': {
                'functions': FEDERATION_ENTITY_FUNCTIONS
            }
        },
        "client": {
            'class': FederationEntityClient,
            'kwargs': {
                "services": FEDERATION_ENTITY_SERVICES
            }
        },
        "server": {
            'class': FederationEntityServer,
            'kwargs': {
                "metadata": {
                },
                "endpoint": LEAF_ENDPOINT
            }
        }
    },
    "trust_mark_issuer": {
        'class': TrustMarkIssuer,
        'kwargs': {
            "trust_marks": {
                TM_ID: {"ref": "https://refeds.org/sirtfi"}
            },
            'server': {
                'class': FederationEntityServer,
                'kwargs': {
                    "endpoint": {
                        "status": {
                            "path": "status",
                            "class": TrustMarkStatus,
                            "kwargs": {"client_authn_method": None},
                        }
                    },
                }
            }
        }
    }
}

class TestCombo():

    @pytest.fixture(autouse=True)
    def create_entity(self):
        #
        self.combo = Combo(config=CONFIG)
        self.tmi = self.combo['trust_mark_issuer']

    def test_setup(self):
        assert self.combo
        assert self.tmi

    def test_create_trust_mark_self_signed(self):
        _trust_mark = self.tmi.self_signed_trust_mark(
            id='https://openid.net/certification',
            logo_uri=("http://openid.net/wordpress-content/uploads/2016/05/"
                      "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg")
        )
        # Unpack and verify the Trust Mark
        _mark = self.tmi.server.endpoint['status'].unpack_trust_mark(_trust_mark)

        assert isinstance(_mark, TrustMark)
        assert _mark["id"] == "https://openid.net/certification"
        assert _mark['iss'] == _mark['sub']
        assert _mark['iss'] == self.tmi.entity_id
        assert set(_mark.keys()) == {'iss', 'sub', 'iat', 'id', 'logo_uri'}

    def test_create_unpack_trust_3rd_party(self):
        _sub = "https://op.ntnu.no"
        self.tmi.trust_marks["https://refeds.org/sirtfi"] = {}
        _trust_mark = self.tmi.create_trust_mark("https://refeds.org/sirtfi", _sub)

        _mark = self.tmi.server.endpoint['status'].unpack_trust_mark(_trust_mark, _sub)

        assert isinstance(_mark, TrustMark)
        assert set(self.tmi.issued.keys()) == {"https://refeds.org/sirtfi"}
        assert set(self.tmi.issued['https://refeds.org/sirtfi'].keys()) == {_sub}

    def test_process_request(self):
        _sub = "https://op.ntnu.no"
        self.tmi.trust_marks["https://refeds.org/sirtfi"] = {}
        _trust_mark = self.tmi.create_trust_mark("https://refeds.org/sirtfi", _sub)

        resp = self.tmi.server.endpoint['status'].process_request({'trust_mark': _trust_mark})
        assert resp == {'response': '{"active": true}'}

