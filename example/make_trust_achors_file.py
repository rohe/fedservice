#!/usr/bin/env python3
import json
import os
import sys

from cryptojwt.key_jar import init_key_jar

ENTITY = {
    "RPA": ['rp', './rp.py', "conf_auto.json", "auto"],
    "RPE": ['rp', './rp.py', "conf_expl.json", "expl"],
    "OP": ['op', './op.py', 'conf.json', ""],
    "LU": ['intermediate', './entity.py', "conf_lu.json", "lu"],
    "UMU": ['intermediate', './entity.py', "conf_umu.json", "umu"],
    "SEID": ["ta", "./entity.py", "conf_seid.json", "seid"],
    "SWAMID": ["ta", "./entity.py", "conf_swamid.json", "swamid"],
}

file_name = "trusted_roots.json"

_anchor = {}

for ta in ["SEID", "SWAMID"]:
    _dir, _, _conf_file, _ = ENTITY[ta]
    _conf = json.loads(open(os.path.join(_dir, _conf_file)).read())
    _entity_id = _conf["federation"]["entity_id"]
    _keyjar = init_key_jar(**_conf["federation"]["keys"])
    _anchor[_entity_id] = _keyjar.export_jwks()

for ent in ['RPA', 'RPE', 'OP', 'LU',' UMU']:
    _dir, _, _conf_file, _sub = ENTITY[ta]
    _name = os.path.join(_dir, _sub, file_name)
    with open(_name, "w") as fp:
        fp.write(json.dumps(_anchor, sort_keys=True, indent=2))
        fp.close()