#!/usr/bin/env python3
import json
import sys

from cryptojwt.jws.jws import factory

_jws = factory(sys.stdin.read())
print(json.dumps(_jws.jwt.payload(), indent=4, sort_keys=True))

