#!/usr/bin/env python3
import json

from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-t', "--trusted_roots")
    parser.add_argument('-e', dest='entity_id')
    parser.add_argument('-c', dest='config', action='store_true')
    parser.add_argument('-s', dest='sub', action='store_true')
    parser.add_argument('-a', dest='fed_api')
    args = parser.parse_args()

    kwargs = {}
    if args.insecure:
        kwargs['insecure'] = True
    if args.trusted_roots:
        kwargs['trust_anchors'] = args.trusted_roots
    else:
        kwargs["trust_anchors"] = {}

    _collector = Collector(**kwargs)

    _info = None
    if args.config:
        _jws = _collector.get_configuration_information(args.entity_id)
        entity_statement = verify_self_signed_signature(_jws)
        json_str = json.dumps(entity_statement, indent=2)
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))

    if args.sub:
        _info = _collector.get_entity_statement(args.fed_api, args.entity_id, args.sub)
