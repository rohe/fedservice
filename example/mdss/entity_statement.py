#!/usr/bin/env python3

import json
import os
import sys

from cryptojwt import KeyJar

from fedservice import create_entity_statement

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def create(iss, sub, domain, root_dir):
    kj = KeyJar()

    iss_id = "https://{}".format(iss)
    iss_jwks_file = os.path.join(root_dir, iss, "{}.jwks.json".format(iss))
    kj.import_jwks_as_json(open(iss_jwks_file).read(), iss_id)

    sub_id = "https://{}".format(sub)
    sub_jwks_file = os.path.join(root_dir, iss, "{}.jwks.json".format(sub))
    kj.import_jwks_as_json(open(sub_jwks_file).read(), sub_id)

    metadata_file = os.path.join(root_dir, iss, "{}.metadata.json".format(sub))
    if os.path.isfile(metadata_file):
        metadata = json.loads(open(metadata_file).read())
    else:
        metadata = None

    if metadata:
        for typ, conf in metadata.items():
            for key, val in conf.items():
                if '<DOMAIN>' in val:
                    metadata[typ][key] = val.replace('<DOMAIN>', domain)

    policy_file = os.path.join(root_dir, iss, "{}.policy.json".format(sub))
    if os.path.isfile(policy_file):
        policy = json.loads(open(policy_file).read())
    else:
        policy = None

    authority_file = os.path.join(root_dir, iss, "{}.authority.json".format(sub))
    if os.path.isfile(authority_file):
        _auth = json.loads(open(authority_file).read())
        for key, vals in _auth.items():
            if '<DOMAIN>' in key:
                _key = key.replace('<DOMAIN>', domain)
                _vals = [v.replace('<DOMAIN>', domain) for v in vals]
                del _auth[key]
                _auth[_key] = _vals

        _jwt = create_entity_statement(iss_id, sub_id, kj, metadata, policy, _auth)
    else:
        _jwt = create_entity_statement(iss_id, sub_id, kj, metadata, policy)

    return _jwt


def write_entity_statement(iss, sub, domain, root_dir):
    _jwt = create(iss, sub, domain, root_dir)
    output = os.path.join(BASE_PATH, iss, sub)
    fp = open(output, "w")
    fp.write(_jwt)
    fp.close()


if __name__ == '__main__':
    # domain is typically something like 127.0.0.1:5000 (default Flask)
    domain = sys.argv[1]

    root_dir = os.path.join(BASE_PATH, 'data')
    for iss in os.listdir(root_dir):
        path = os.path.join(root_dir, iss)
        if os.path.isdir(path):
            for sub in os.listdir(path):
                if sub.endswith('.json'):
                    continue
                else:
                    create(iss, sub, domain, root_dir)
