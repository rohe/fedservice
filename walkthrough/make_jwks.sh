#!/usr/bin/env bash

../script/make_jwks.py -o edu/fed/jwks.json
../script/make_jwks.py -o com/a/jwks.json
../script/make_jwks.py -o com/a/rp/jwks.json
../script/make_jwks.py -o org/b/jwks.json
../script/make_jwks.py -o org/b/op/jwks.json
