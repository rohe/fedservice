#!/usr/bin/env python3
import sys

from cryptojwt.key_jar import build_keyjar

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

keyjar = build_keyjar(KEYSPEC)
print(keyjar.export_jwks_as_json(private=True))
