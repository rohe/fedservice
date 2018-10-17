#!/usr/bin/env python3
import argparse
import json
import logging

from cryptojwt.key_jar import KeyJar
from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.data import JsonLexer

from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.verify import flatten_metadata
from fedservice.entity_statement.verify import verify_leaf_status
from fedservice.entity_statement.verify import verify_trust_chain

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='trust_root',
                        help="A file with the trusted roots")
    parser.add_argument("-e", dest='entity_type', default='openid_client')
    parser.add_argument("entity_id", help="Entity ID")
    args = parser.parse_args()

    # wf = WebFinger(ServiceContext(), None)

    # Put the trust roots in a Key Jar
    trust_roots = json.loads(open(args.trust_root).read())
    kj = KeyJar()
    for iss, jwks in trust_roots.items():
        kj.import_jwks(jwks, iss)
    _collector = Collector(trusted_roots=trust_roots)

    _jarr = _collector.load_entity_statements(args.entity_id, args.entity_id)
    _node = _collector.collect_entity_statements(_jarr)

    branch = {}

    for path in _node.paths():
        # Verify the trust chain
        path.reverse()
        ves = verify_trust_chain(path, kj)
        try:
            leaf_ok = verify_leaf_status(ves)
        except ValueError as err:
            logger.warning(err)
        else:
            if not leaf_ok:
                continue

        res = flatten_metadata(ves, args.entity_type, strict=False)

        if res:
            tr = ves[0]['iss']
            _dict = res.unprotected_and_protected_claims()
            try:
                branch[tr].append(_dict)
            except KeyError:
                branch[tr] = [_dict]

    json_str = json.dumps(branch, indent=2)
    print(highlight(json_str, JsonLexer(), TerminalFormatter()))
