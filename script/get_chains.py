#!/usr/bin/env python3
import argparse
import json

from fedservice.entity.function import apply_policies

from fedservice.entity.function import verify_trust_chains

from fedservice.entity.function import collect_trust_chains
from idpyoidc.logging import configure_logging

from fedservice.utils import make_federation_entity

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
    parser.add_argument('-l', dest='logging', action='store_true')
    parser.add_argument(dest="url")
    args = parser.parse_args()

    if args.logging:
        logger = configure_logging(config=LOGGING).getChild(__name__)

    trust_anchors = json.loads(open(args.trusted_roots_file).read())

    # Creates an entity that can do the collecting of information
    federation_entity = make_federation_entity(entity_id="https://localhost",
                                               trust_anchors=trust_anchors)

    if args.insecure:
        federation_entity.keyjar.httpc_params = {"verify": False}

    chains, leaf_ec = collect_trust_chains(federation_entity, entity_id=args.url)
    if len(chains) == 0:
        print("No chains")

    trust_chains = verify_trust_chains(federation_entity, chains, leaf_ec)
    trust_chains = apply_policies(federation_entity, trust_chains)

    for trust_chain in trust_chains:
        print(20 * "=", trust_chain.anchor, 20 * "=")
        for node in trust_chain.verified_chain:
            # pretty print JSON
            print(json.dumps(node, sort_keys=True, indent=4))
