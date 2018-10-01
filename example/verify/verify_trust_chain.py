#!/usr/bin/env python3
import argparse
import json

from fedservice.entity_statement.le import LessOrEqual
from fedservice.entity_statement.verify import verify_trust_chain

from cryptojwt.key_jar import KeyJar


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='trust_root',
                        help="A file with the trusted roots")
    parser.add_argument("entity_statement", nargs='+', help="Entity Statement")
    args = parser.parse_args()

    # expect the input order to be entity - *intermediates - trust root
    args.entity_statement.reverse()

    trust_roots = json.loads(open(args.trust_root).read())
    kj = KeyJar()
    for iss, jwks in trust_roots.items():
        kj.import_jwks(jwks, iss)

    es_list = [open(e).read().strip() for e in args.entity_statement]

    ves = verify_trust_chain(es_list, kj)

    print("Chain length: {}".format(len(ves)))

    # start with the trust root
    res = LessOrEqual()
    res.le = ves[0]['metadata']['openid-client']
    for es in ves[1:]:
        res = LessOrEqual(sup=res)
        if res.eval(es['metadata']['openid-client']) is False:
            raise ValueError('Could not flatten')

    if res:
        print(res.protected_claims())
        print(40*'-')
        print(res.unprotected_and_protected_claims())
