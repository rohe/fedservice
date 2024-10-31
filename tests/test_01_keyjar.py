from cryptojwt.key_jar import init_key_jar

from fedservice.keyjar import import_jwks

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]},
    {"type": "EC", "crv": "P-521", "use": ["sig"]},
]


def test():
    _keyjar = init_key_jar(key_defs=KEYSPEC)
    _jwks = _keyjar.export_jwks()
    keyjar = import_jwks(_keyjar, _jwks, "")
    assert len(keyjar) == 5
