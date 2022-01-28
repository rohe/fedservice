import os

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
import pytest

from fedservice.entity import FederationEntity
from fedservice.entity.fetch import Fetch
from fedservice.entity.status import SelfSigned
from fedservice.entity.status import Status
from fedservice.entity_statement.trust_mark import create_trust_mark
from fedservice.entity_statement.trust_mark import unpack_trust_mark
from fedservice.message import TrustMark
from fedservice.fetch_entity_statement.fs2 import read_info
from fedservice.trust_mark_issuer import TrustMarkIssuer

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')
ANCHOR = {'https://feide.no': read_info(os.path.join(ROOT_DIR, 'feide.no'), "feide.no", "jwks")}


def test_create_trust_mark_self_signed():
    _entity_id = "https://example.com/op"
    _tm = TrustMark(
        id="https://openid.net/certification/op",
        sub=_entity_id,
        mark="http://openid.net/wordpress-content/uploads/2016/05/oid-l-certification-mark-l-cmyk" \
             "-150dpi-90mm.jpg",
        ref="https://openid.net/wordpress-content/uploads/2015/09/RolandHedberg-pyoidc-0.7.7"
            "-Basic-26-Sept-2015.zip"
    )

    _key_jar = build_keyjar(KEYSPEC, issuer_id=_entity_id)

    # Create the Signed JWT representing the Trust Mark
    _jwt0 = JWT(key_jar=_key_jar, iss=_entity_id, lifetime=3600)
    _jws = _jwt0.pack(_tm)

    # Unpack and verify the Trust Mark
    _jwt1 = JWT(key_jar=_key_jar, msg_cls=TrustMark, allowed_sign_algs=["RS256"])
    res_tm = _jwt1.unpack(_jws)
    res_tm.verify(entity_id=_entity_id)

    assert isinstance(res_tm, TrustMark)
    assert res_tm["id"] == "https://openid.net/certification/op"


def test_create_unpack_trust_mark_self_signed():
    _entity_id = "https://example.com/op"
    _key_jar = build_keyjar(KEYSPEC, issuer_id=_entity_id)

    _tm = create_trust_mark(_entity_id, _key_jar,
                            trust_mark_id="https://openid.net/certification/op",
                            trust_mark=("http://openid.net/wordpress-content/uploads/2016/05/"
                                        "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg")
                            )

    _tm_inst = unpack_trust_mark(_tm, _key_jar, _entity_id)

    assert isinstance(_tm_inst, TrustMark)


def test_create_unpack_trust_3rd_party():
    _iss = "https://feide.no"
    _sub = "https://op.ntnu.no"
    _key_jar = build_keyjar(KEYSPEC, issuer_id=_iss)

    _tm = create_trust_mark(_iss, _key_jar, subject=_sub,
                            trust_mark_id="https://openid.net/certification/op",
                            trust_mark=("http://openid.net/wordpress-content/uploads/2016/05/"
                                        "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg")
                            )

    _tm_inst = unpack_trust_mark(_tm, _key_jar, _sub)

    assert isinstance(_tm_inst, TrustMark)


ENTITY_ID = "https://op.ntnu.no"

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"

CONFIG_3RD = {
    "entity_id": ENTITY_ID,
    "keys": {"uri_path": "static/fed_jwks.json", "key_defs": KEYSPEC},
    "endpoint": {
        "status": {
            "path": "status",
            "class": Status,
            "kwargs": {
                "client_authn_method": None,
                "db": {
                    "class": "fedservice.trust_mark_issuer.FileDB",
                    "kwargs": {TM_ID: "sirtifi"}
                },
            },
        },
        "fetch": {
            "path": "fetch",
            "class": Fetch,
            "kwargs": {"client_authn_method": None},
        }
    },
    "trusted_roots": ANCHOR,
    "authority_hints": ['https://ntnu.no'],
    "entity_type": 'trust_mark_issuer',
    "trust_marks": {
        TM_ID : {"ref": "https://refeds.org/sirtfi"}
    },
    "trust_mark_db": {
        "class": "fedservice.trust_mark_issuer.FileDB",
        "kwargs": {TM_ID: "sirtifi"}
    }
}

CONFIG_SELF_SIGN = {
    "entity_id": ENTITY_ID,
    "keys": {"uri_path": "static/fed_jwks.json", "key_defs": KEYSPEC},
    "endpoint": {
        "status": {
            "path": "status",
            "class": SelfSigned,
            "kwargs": {
                "client_authn_method": None,
            },
        },
        "fetch": {
            "path": "fetch",
            "class": Fetch,
            "kwargs": {"client_authn_method": None},
        }
    },
    "trusted_roots": ANCHOR,
    "authority_hints": ['https://ntnu.no'],
    "entity_type": 'trust_mark_issuer',
    "self_signed_trust_marks": {
        "function": "fedservice.trust_mark_issuer.self_signed_trust_mark",
        "kwargs": {
            "https://openid.net/certification/op": {
                "mark": ("http://openid.net/wordpress-content/uploads/2016/05/"
                         "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg"),
                "ref": ("https://openid.net/wordpress-content/uploads/2015/09/"
                        "RolandHedberg-pyoidc-0.7.7-Basic-26-Sept-2015.zip")
            }
        }
    }
}


class TestSelfSigned(object):
    @pytest.fixture(autouse=True)
    def create_issuer(self):
        self.entity = FederationEntity(config=CONFIG_SELF_SIGN)

    def test_get_trust_mark_self_signed(self):
        # Verify the self signed trust marks
        for _jws in self.entity.server_get('context').signed_trust_marks:
            _jwt = factory(_jws)
            _payload = _jwt.jwt.payload()
            _tm = TrustMark(**_payload)
            assert _tm.verify()

    def test_verify_using_id(self):
        _endpoint = self.entity.get_endpoint("status")
        _resp = _endpoint.process_request({"id": "https://openid.net/certification/op",
                                           "sub": self.entity.context.entity_id})
        assert _resp == {'response_args': {"active": True}}

    def test_using_trust_mark(self):
        _jws = self.entity.server_get('context').signed_trust_marks[0]
        _endpoint = self.entity.get_endpoint("status")
        _resp = _endpoint.process_request({"trust_mark": _jws})
        assert _resp == {'response_args': {"active": True}}


class Test3rdParty(object):
    @pytest.fixture(autouse=True)
    def create_issuer(self):
        self.id = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"
        self.tmi = TrustMarkIssuer(config=CONFIG_3RD)

    def test_get_trust_mark_3rd_party(self):
        # Create the Signed JWT representing the Trust Mark

        _jws = self.tmi.create_trust_mark(self.id, "https://example.com")
        _jwt = factory(_jws)
        _payload = _jwt.jwt.payload()
        _tm = TrustMark(**_payload)
        assert _tm.verify()

    def test_verify_using_id(self):
        _jws = self.tmi.create_trust_mark(self.id, self.tmi.context.entity_id)

        _endpoint = self.tmi.get_endpoint("status")
        _resp = _endpoint.process_request({"id": self.id,
                                           "sub": self.tmi.context.entity_id})
        assert _resp == {'response_args': {"active": True}}

    def test_using_trust_mark(self):
        _jws = self.tmi.create_trust_mark(self.id, self.tmi.context.entity_id)

        _endpoint = self.tmi.get_endpoint("status")
        _resp = _endpoint.process_request({"trust_mark": _jws})
        assert _resp == {'response_args': {"active": True}}
