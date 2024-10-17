#!/usr/bin/env python3
import json

from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.utils import make_federation_entity

def do_subordinates(federation_entity, entity_id) -> dict:
    _collector = federation_entity.get_function("trust_chain_collector")
    # Read the entity configuration
    _jws = _collector.get_entity_configuration(entity_id)
    # Verify the self signed signature
    entity_configuration = verify_self_signed_signature(_jws)

    if "federation_list_endpoint" in entity_configuration["metadata"]["federation_entity"]:
        res = {}
        endpoint = entity_configuration["metadata"]["federation_entity"]["federation_list_endpoint"]
        # Ask the superior for the subordinates statement
        _list_response = federation_entity.client.do_request('list', endpoint=endpoint)
        if _list_response:
            for sub in _list_response:
                res.update(do_subordinates(federation_entity, sub))
        return res
    else:
        return {entity_id: {}}

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-t', "--trust_anchors_file")
    parser.add_argument(dest="entity_id")
    args = parser.parse_args()

    if not args.entity_id:
        print("Need an entity_id to work with")

    if args.trust_anchors_file:
        trust_anchors = json.loads(open(args.trust_anchors_file).read())
    else:
        trust_anchors = {}

    federation_entity = make_federation_entity(entity_id="https://localhost",
                                               trust_anchors=trust_anchors)
    if args.insecure:
        federation_entity.keyjar.httpc_params = {"verify": False}

    res = do_subordinates(federation_entity, entity_id=args.entity_id)

    print(res)