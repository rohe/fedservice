#!/usr/bin/env python3
import os
import shlex
import subprocess
import sys
from time import sleep

ENTITY = {
    "RPA": ['rp', './rp.py', "conf_auto.json"],
    "RPE": ['rp', './rp.py', "conf_expl.json"],
    "OP": ['op', './op.py', 'conf.json'],
    "LU": ['intermediate', './entity.py', "conf_lu.json"],
    "UMU": ['intermediate', './entity.py', "conf_umu.json"],
    "SEID": ["ta", "./entity.py", "conf_seid.json"],
    "SWAMID": ["ta", "./entity.py", "conf_swamid.json"],
}


def start(ents):
    cwd = os.getcwd()

    for ent in ents:
        _dir, _com, _conf = ENTITY[ent]
        os.chdir(_dir)
        print(os.getcwd())
        _args = [_com, ent, _conf]
        print(_args)
        _res = subprocess.Popen(_args, env=dict(os.environ))
        print(_res)
        sleep(1)
        os.chdir(cwd)


def kill(ents):
    _process = subprocess.Popen(['ps', '-ax'], stdout=subprocess.PIPE)
    output, error = _process.communicate()
    # print(output)
    for line in output.splitlines():
        for _ent in ents:
            if _ent in str(line):
                pid = int(line.split(None, 1)[0])
                os.kill(pid, 9)
                break


if __name__ == "__main__":
    if sys.argv[1] == "start":
        start(sys.argv[2:])
    elif sys.argv[1] == "kill":
        kill(sys.argv[2:])
