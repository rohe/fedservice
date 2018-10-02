#!/usr/bin/env python3
import argparse
import json

from cryptojwt.key_jar import KeyJar

from fedservice.entity_statement.create import create_entity_statement

parser = argparse.ArgumentParser()
parser.add_argument('-j', dest='jwks',
                    help="A file containing a JWKS for this entity")
parser.add_argument('-m', dest='msg', help="The basic message")
parser.add_argument('-a', dest='authority', help="authority_hints")
parser.add_argument('-i', dest='iss')
parser.add_argument('-s', dest='sub')
parser.add_argument('-k', dest='sub_jwks',
                    help="A file containing a JWKS for the subject")
parser.add_argument('-t', dest='lifetime', default=86400)
args = parser.parse_args()

kj = KeyJar()
kj.import_jwks_as_json(open(args.jwks).read(), args.iss)
kj.import_jwks_as_json(open(args.sub_jwks).read(), args.sub)

msg = json.loads(open(args.msg).read())
if args.authority:
    _auth = json.loads(open(args.authority).read())
    _jwt = create_entity_statement(msg["metadata"], args.iss, args.sub, kj,
                                   _auth)
else:
    _jwt = create_entity_statement(msg["metadata"], args.iss, args.sub, kj)

print(_jwt)
