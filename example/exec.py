#!/usr/bin/env python3
import json
import os
import shlex
import subprocess
import sys
from time import sleep

ENTITY = json.loads(open("entities.json", 'r').read())

def start(ents):
    cwd = os.getcwd()

    for ent in ents:
        _dir, _com, _conf, _sub = ENTITY[ent]
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
    elif sys.argv[1] == "kill" or sys.argv[1] == "stop":
        kill(sys.argv[2:])
