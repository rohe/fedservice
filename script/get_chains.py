#!/usr/bin/env python3
import argparse
import json

from oidcop.logging import configure_logging

from fedservice import branch2lists
from fedservice import eval_chain
from fedservice.entity import FederationEntity
from fedservice.entity_statement.collect import verify_self_signed_signature

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    "root": {
        "handlers": ["console"],
        "level": "DEBUG"
    },
    "loggers": {
        "idp": {
            "level": "DEBUG"}
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",

            "formatter": "default"},
    },
    "formatters": {
        "default": {
            "format": '%(asctime)s %(name)s %(levelname)s %(message)s'}
    }
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-t', dest='trusted_roots_file')
    parser.add_argument('-e', dest='entity_type')
    parser.add_argument('-o', dest='opponent_entity_type')
    parser.add_argument('-l', dest='logging', action='store_true')
    parser.add_argument(dest="url")
    args = parser.parse_args()

    if args.logging:
        logger = configure_logging(config=LOGGING).getChild(__name__)

    trusted_roots = json.loads(open(args.trusted_roots_file).read())

    # Creates an entity that can do the collecting of information
    conf = {
        "trusted_roots": trusted_roots,
        "entity_type": args.entity_type
    }
    federation_entity = FederationEntity('Collector', config=conf)

    if args.insecure:
        federation_entity.collector.httpc_params = {"verify": False}

    jws = federation_entity.get_configuration_information(args.url)
    metadata = verify_self_signed_signature(jws)

    _tree = federation_entity.collect_statement_chains(metadata['iss'], metadata)
    chains = branch2lists(_tree)
    for c in chains:
        c.append(jws)

    statements = [eval_chain(c, federation_entity.context.keyjar, args.opponent_entity_type) for c
                  in chains]

    for statement in statements:
        if statement is None:
            continue
        print(20 * "=", statement.anchor, 20 * "=")
        for node in statement.verified_chain:
            # pretty print JSON
            print(json.dumps(node, sort_keys=True, indent=4))
