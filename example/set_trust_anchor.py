#!/usr/bin/env python3
import json
import os
import sys

from fedservice.example_utils import get_federation_config
from fedservice.example_utils import create_and_write_private_and_public_key_sets

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

ENTITY = json.loads(open("entities.json", 'r').read())

target = sys.argv[1]
target_conf = get_federation_config(ENTITY, target)

_anchor = {}
for anchor in sys.argv[2:]:
    _conf = get_federation_config(ENTITY, anchor)
    _keyjar = create_and_write_private_and_public_key_sets(ENTITY, anchor, _conf)
    _entity_id = _conf["entity_id"]
    _anchor[_entity_id] = _keyjar.export_jwks()

_fname = os.path.join(BASE_PATH, ENTITY[target][0], target_conf["trusted_roots"])
with open(_fname, "w") as fp:
    fp.write(json.dumps(_anchor, sort_keys=True, indent=2))
