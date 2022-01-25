#!/usr/bin/env python3
import os
import subprocess
import sys
from time import sleep

ENTITY = {
    "RPA": ['rp', './rp.py', "conf_auto.json"],
    "RPE": ['rp', './rp.py', "conf_expl.json"],
    "OP": ['op', './op.py', 'conf.json'],
    "LU": ['intermediate','./entity.py', "conf_lu.json"],
    "UMU": ['intermediate','./entity.py', "conf_umu.json"],
    "SEID": ["ta", "./entity.py", "conf_seid.json"],
    "SWAMID": ["ta", "./entity.py", "conf_swamid.json"],
}

cwd = os.getcwd()

for ent in sys.argv[1:]:
    _dir, _com, _conf = ENTITY[ent]
    os.chdir(_dir)
    print(os.getcwd())
    _args = [_com, ent, _conf, "&"]
    print(_args)
    _res = subprocess.run(" ".join(_args), shell=True)
    print(_res)
    sleep(1)
    os.chdir(cwd)
