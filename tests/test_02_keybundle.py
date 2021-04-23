from cryptojwt.jws.jws import factory
from cryptojwt.key_bundle import build_key_bundle
from cryptojwt.key_jar import build_keyjar
import responses

from fedservice.keybundle import KeyBundle

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.org/op"

KEY_JAR = build_keyjar(KEYSPEC, issuer_id=ISSUER)


class Response():
    def __init__(self, headers, text):
        self.headers = headers
        self.text = text


def test_signed_jwks():
    _bundle = build_key_bundle(key_conf=KEYSPEC)
    _keys = [k.serialize() for k in _bundle.keys()]

    federation_key_bundle = KeyBundle(keys=_keys, federation_keys=KEY_JAR)
    _jws = federation_key_bundle.signed_jwks(issuer=ISSUER)

    _jwt = factory(_jws)
    assert set(_jwt.jwt.payload().keys()) == {"keys", "iat", "iss"}


def test_unpack_signed_jwks():
    _bundle = build_key_bundle(key_conf=KEYSPEC)
    _keys = [k.serialize() for k in _bundle.keys()]

    federation_key_bundle = KeyBundle(keys=_keys, federation_keys=KEY_JAR)
    _jws = federation_key_bundle.signed_jwks(issuer=ISSUER)

    _signed_jwks_url = 'https://foobar.com/signed_jwks.json'

    _kb = KeyBundle(federation_keys=KEY_JAR, source=_signed_jwks_url)

    with responses.RequestsMock() as rsps:
        rsps.add("GET", _signed_jwks_url, body=_jws, status=200,
                 adding_headers={"Content-Type": "application/jwt"})

        _kb.do_remote()

    assert len(_kb) == 2
