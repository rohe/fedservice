#!/usr/bin/env python3
from cryptojwt import KeyJar

key_jar = KeyJar()
key_jar.import_jwks_from_file("../flask_op/static/fed_keys.json", "")
_jwks = key_jar.export_jwks_as_json(issuer="")
with open('base_data/umu.se/https%3A%2F%2F127.0.0.1%3A5000/jwks.json', "w") as fp:
    fp.write(_jwks)

key_jar = KeyJar()
key_jar.import_jwks_from_file("../flask_rp/static/fed_keys.json", "")
_jwks = key_jar.export_jwks_as_json(issuer="")
with open('base_data/lu.se/https%3A%2F%2F127.0.0.1%3A4000/jwks.json', "w") as fp:
    fp.write(_jwks)
