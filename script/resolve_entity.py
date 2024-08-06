#!/usr/bin/env python3
import json

from fedservice.utils import make_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-t', "--trust_anchor")
    parser.add_argument('-r', "--resolver")
    parser.add_argument('-T', "--trust_anchor_file")
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
        trust_anchors=trust_anchors
    )

    if args.insecure:
        # federation_entity.keyjar.httpc_params = {"verify": False}
        # federation_entity.keyjar.httpc_params = {"verify": False}
        # federation_entity.httpc_params = {"verify": False}
        federation_entity.client.httpc_params = {"verify": False}

    _resolver = federation_entity.get_service("resolve")

    res = _resolver.get_request_parameters({
        "sub": args.entity_id,
        "anchor": args.trust_anchor},
        endpoint=f"{args.resolver}/resolve"
    )
    print(res)

    resolve_resp = federation_entity.do_request("resolve",
                                                request_args={
                                                    "sub": args.entity_id,
                                                    "anchor": args.trust_anchor},
                                                endpoint=f"{args.resolver}/resolve"
                                                )
    print(resolve_resp)