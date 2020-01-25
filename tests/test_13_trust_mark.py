import os

from cryptojwt import JWT
from cryptojwt.key_jar import build_keyjar

from fedservice import FederationEntity
from fedservice.entity_statement.trust_mark import create_trust_mark
from fedservice.entity_statement.trust_mark import get_trust_mark
from fedservice.entity_statement.trust_mark import unpack_trust_mark
from fedservice.message import TrustMark
from fedservice.metadata_api.fs2 import read_info

from .utils import DummyCollector
from .utils import Publisher

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

    _key_jar = build_keyjar(KEYSPEC, owner=_entity_id)

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
    _key_jar = build_keyjar(KEYSPEC, owner=_entity_id)

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
    _key_jar = build_keyjar(KEYSPEC, owner=_iss)

    _tm = create_trust_mark(_iss, _key_jar, subject=_sub,
                            trust_mark_id="https://openid.net/certification/op",
                            trust_mark=("http://openid.net/wordpress-content/uploads/2016/05/"
                                        "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg")
                            )

    _tm_inst = unpack_trust_mark(_tm, _key_jar, _sub)

    assert isinstance(_tm_inst, TrustMark)


def test_get_trust_mark_self_signed():
    _entity_id = "https://op.ntnu.no"
    _key_jar = build_keyjar(KEYSPEC, owner=_entity_id)

    federation_entity = FederationEntity(
        _entity_id, key_jar=_key_jar, trusted_roots=ANCHOR,
        authority_hints=['https://ntnu.no'],
        entity_type='openid_relying_party',
        httpd=Publisher(ROOT_DIR),
        opponent_entity_type='openid_relying_party')

    federation_entity.collector = DummyCollector(
        httpd=Publisher(ROOT_DIR),
        trusted_roots=ANCHOR,
        root_dir=ROOT_DIR)

    _tm = TrustMark(
        id="https://openid.net/certification/op",
        sub=_entity_id,
        mark=("http://openid.net/wordpress-content/uploads/2016/05/"
              "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg"),
        ref=("https://openid.net/wordpress-content/uploads/2015/09/"
             "RolandHedberg-pyoidc-0.7.7-Basic-26-Sept-2015.zip")
    )

    # Create the Signed JWT representing the Trust Mark
    _jwt0 = JWT(key_jar=_key_jar, iss=_entity_id, lifetime=3600)
    _jws = _jwt0.pack(_tm)

    trust_anchor_id = list(ANCHOR.keys())[0]

    _tm = get_trust_mark(federation_entity, _jws, _entity_id, trust_anchor_id)

    assert isinstance(_tm, TrustMark)


def test_get_trust_mark_3rd_party():
    _iss = "https://feide.no"
    _sub = "https://op.ntnu.no"

    _key_jar = build_keyjar(KEYSPEC, owner=_iss)

    federation_entity = FederationEntity(
        _iss, key_jar=_key_jar, trusted_roots=ANCHOR,
        authority_hints=['https://ntnu.no'],
        entity_type='openid_relying_party',
        httpd=Publisher(ROOT_DIR),
        opponent_entity_type='openid_relying_party')

    federation_entity.collector = DummyCollector(
        httpd=Publisher(ROOT_DIR),
        trusted_roots=ANCHOR,
        root_dir=ROOT_DIR)

    _tm = TrustMark(
        id="https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf",
        sub=_sub,
    )

    # Create the Signed JWT representing the Trust Mark
    _jwt0 = JWT(key_jar=_key_jar, iss=_iss, lifetime=3600)
    _jws = _jwt0.pack(_tm)

    trust_anchor_id = list(ANCHOR.keys())[0]

    _tm = get_trust_mark(federation_entity, _jws, _sub, trust_anchor_id)

    assert isinstance(_tm, TrustMark)
