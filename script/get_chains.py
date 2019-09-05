#!/usr/bin/env python3
import json

from fedservice import FederationEntity
from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.entity_statement.verify import eval_chain

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-t', dest='trusted_roots_file')
    parser.add_argument('-e', dest='entity_type')
    parser.add_argument('-o', dest='opponent_entity_type')
    parser.add_argument(dest="url")
    args = parser.parse_args()

    trusted_roots = json.loads(open(args.trusted_roots_file).read())

    federation_entity = FederationEntity(
        'issuer', trusted_roots=trusted_roots,
        entity_type=args.entity_type,
        opponent_entity_type=args.opponent_entity_type)

    jws = federation_entity.get_configuration_information(args.url)
    metadata = verify_self_signed_signature(jws)

    _tree = federation_entity.collect_statement_chains(metadata['iss'], jws)
    chains = branch2lists(_tree)
    statements = [eval_chain(c, federation_entity.key_jar, args.opponent_entity_type) for c in
                  chains]

    for statement in statements:
        print(20 * "=", statement.fo, 20 * "=")
        # pretty print JSON
        print(json.dumps(statement.metadata, sort_keys=True, indent=4))
