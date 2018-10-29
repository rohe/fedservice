#!/usr/bin/env python3
import json
import os
import sys

from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.data import JsonLexer

from fedservice import create_federation_entity


def get_sub(token):
    _jwt = factory(token)

    if _jwt:
        return json.loads(as_unicode(_jwt.jwt.part[1]))['sub']
    else:
        return ''


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-t', dest='trusted_roots')
    parser.add_argument('-e', dest='entity_type')
    parser.add_argument('-o', dest='opponent_entity_type')
    parser.add_argument('-f', dest="msg", help="The message")
    args = parser.parse_args()

    federation_entity = create_federation_entity(
        'issuer', trusted_roots=args.trusted_roots,
        entity_type=args.entity_type,
        opponent_entity_type=args.opponent_entity_type)

    if not args.msg:  # If nothing specified assume stdin
        message = sys.stdin.read()
    elif args.msg == "-":
        message = sys.stdin.read()
    else:
        if os.path.isfile(args.msg):
            message = open(args.msg).read().strip("\n")
        else:
            message = args.msg

    _msg = message.strip()
    _msg = _msg.strip('"')

    print('='*20, get_sub(_msg), '='*20)
    # should only return one item not a list
    _node = federation_entity.collect_entity_statements(_msg)

    _res = {}
    for fo, statements in federation_entity.eval_paths(_node).items():
        _res[fo] = [s.le for s in statements]

    json_str = json.dumps(_res, indent=2)
    print(highlight(json_str, JsonLexer(), TerminalFormatter()))
