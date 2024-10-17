#!/usr/bin/env python3
import json

from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.data import JsonLexer

from fedservice.defaults import federation_services
from fedservice.entity.function import get_entity_endpoint
from fedservice.utils import make_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-f', "--format", action='store_true')
    parser.add_argument('-t', "--trust_anchor")
    parser.add_argument('-T', "--trust_anchor_file")
    parser.add_argument('-r', "--resolver")
    parser.add_argument(dest="entity_id")
    args = parser.parse_args()

    if not args.entity_id:
        print("Need an entity_id to work with")

    if args.trust_anchor_file:
        trust_anchors = json.loads(open(args.trust_anchor_file).read())
    else:
        trust_anchors = {}

    federation_entity = make_federation_entity(
        entity_id="https://localhost",
        trust_anchors=trust_anchors,
        services=federation_services("entity_configuration", "resolve", "entity_statement"),
    )

    if args.insecure:
        federation_entity.client.httpc_params = {"verify": False}

    # Need to find the listing endpoint
    endpoint = get_entity_endpoint(federation_entity, args.resolver, "federation_entity",
                                   "federation_resolve_endpoint")

    resolve_resp = federation_entity.do_request("resolve",
                                                request_args={
                                                    "sub": args.entity_id,
                                                    "anchor": args.trust_anchor},
                                                endpoint=endpoint)
    json_str = json.dumps(resolve_resp.to_dict(), indent=2)
    print(20 * "=" + " Resolver response " + 20 * "=")
    if args.format:
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))
    else:
        print(json_str)

