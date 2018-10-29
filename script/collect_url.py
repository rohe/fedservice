#!/usr/bin/env python3
import json

import requests
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

from fedservice import create_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-t', dest='trusted_roots')
    parser.add_argument('-e', dest='entity_type')
    parser.add_argument('-o', dest='opponent_entity_type')
    parser.add_argument(dest="url")
    args = parser.parse_args()

    federation_entity = create_federation_entity(
        'issuer', trusted_roots=args.trusted_roots,
        entity_type=args.entity_type,
        opponent_entity_type=args.opponent_entity_type)

    if args.insecure:
        response = requests.request('GET', args.url, verify=False)
    else:
        response = requests.request('GET', args.url)

    if response.status_code == 200:
        _msg = response.text.strip('"')
        # should only return one item not a list
        _node = federation_entity.collect_entity_statements([_msg])

        _res = {}
        for key, statems in federation_entity.eval_paths(_node).items():
            _res[key] = [s.le for s in statems]

        json_str = json.dumps(_res, indent=2)
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))
