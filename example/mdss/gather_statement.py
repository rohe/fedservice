#!/usr/bin/env python3
import argparse
import json
import os

from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar

from fedservice import FederationEntity
from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.verify import eval_chain

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'data')

KEY_DEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]}
]


def main(fedent, entity_id, entity_type):
    _jws = fedent.get_configuration_information(entity_id)
    _jwt = factory(_jws)
    msg = _jwt.jwt.payload()
    tree = fedent.collect_statement_chains(entity_id, msg)
    chains = branch2lists((_jws, tree))
    statements = [eval_chain(c, fedent.key_jar, entity_type) for c in chains]
    return statements


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', dest='netloc')
    parser.add_argument('-e', dest='entity_id')
    parser.add_argument('-t', dest="entity_type")
    parser.add_argument('-k', dest='insecure', action='store_true')
    args = parser.parse_args()

    jwks = open(os.path.join(ROOT_DIR, 'swamid', 'swamid.jwks.json')).read()

    ANCHOR = {'https://{}/swamid'.format(args.netloc): json.loads(jwks)}

    my_entity_id = "https://{}/me".format(args.netloc)
    fedent = FederationEntity(
        my_entity_id,
        trusted_roots=ANCHOR,
        authority_hints={'https://ntnu.no': ['https://feide.no']},
        entity_type="",
        opponent_entity_type=args.entity_type,
        key_jar=init_key_jar(key_defs=KEY_DEFS, owner=my_entity_id)
    )

    if args.insecure:
        fedent.key_jar.verify_ssl = False
        fedent.collector.insecure = True

    for statement in main(fedent, args.entity_id, args.entity_type):
        print(20 * "=", statement.fo, 20 * "=")
        print(json.dumps(statement.metadata, indent=4, sort_keys=True))
