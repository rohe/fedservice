#!/usr/bin/env python3
import argparse
import json
import os
import sys
from urllib.parse import quote_plus

from fedservice.example_utils import get_federation_config, create_and_write_private_and_public_key_sets

ENTITY = json.loads(open("entities.json", 'r').read())

parser = argparse.ArgumentParser()
parser.add_argument('-p', dest='policy')
parser.add_argument('-s', dest='subordinate')
parser.add_argument(dest="authority")
args = parser.parse_args()

superior_conf = get_federation_config(ENTITY, args.authority)

if args.policy:
    _policy = json.loads(open(args.policy, 'r').read())
else:
    _policy = None

subordinate_conf = get_federation_config(ENTITY, args.subordinate)
_keyjar = create_and_write_private_and_public_key_sets(ENTITY, args.subordinate, subordinate_conf)

entity_statement = {"jwks":_keyjar.export_jwks()}
if _policy:
    entity_statement.update(_policy)

_ent = ENTITY[args.authority]
_fname = os.path.join(_ent[0], _ent[3], 'subordinate', quote_plus(subordinate_conf["entity_id"]))
with open(_fname, "w") as fp:
    fp.write(json.dumps(entity_statement, sort_keys=True, indent=2))
