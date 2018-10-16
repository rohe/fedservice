#!/usr/bin/env python3
import argparse
import json

from cryptojwt.key_jar import build_keyjar

parser = argparse.ArgumentParser()
parser.add_argument('-s', dest='key_conf_file')
parser.add_argument('-o', dest='out_files', nargs='+')
args = parser.parse_args()

if args.key_conf_file:
    key_conf = json.loads(open(args.key_conf_file).read())
else:
    key_conf = [
        {"type": "RSA", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

_kj = build_keyjar(key_conf=key_conf)

for file in args.out_files:
    with open(file, 'w') as fd:
        fd.write(_kj.export_jwks_as_json(True, ''))