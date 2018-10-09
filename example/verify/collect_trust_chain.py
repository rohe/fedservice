#!/usr/bin/env python3
import argparse
import json

from cryptojwt.key_jar import KeyJar
from oidcservice.oidc.service import WebFinger
from oidcservice.service_context import ServiceContext

from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.verify import flatten_metadata
from fedservice.entity_statement.verify import verify_trust_chain

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='trust_root',
                        help="A file with the trusted roots")
    parser.add_argument("entity_id", help="Entity ID")
    args = parser.parse_args()

    wf = WebFinger(ServiceContext(), None)

    # Put the trust roots in a Key Jar
    trust_roots = json.loads(open(args.trust_root).read())
    kj = KeyJar()
    for iss, jwks in trust_roots.items():
        kj.import_jwks(jwks, iss)
    _collector = Collector(web_finger=wf, trusted_roots=trust_roots)

    _es = _collector.load_entity_statement(args.entity_id, args.entity_id)
    _node = _collector.collect_entity_statements(_es)

    for path in _node.paths():
        trust_root = path[-1]['iss']
        # Verify the trust chain
        ves = verify_trust_chain(path, kj)

        print("Chain length: {}".format(len(ves)))

        res = flatten_metadata(ves, 'openid_client')

        if res:
            _str = "{}{}{}".format(20 * '=', trust_root, 20 * '=')
            print(_str)
            print(res.protected_claims())
            print(len(_str) * '-')
            print(res.unprotected_and_protected_claims())
