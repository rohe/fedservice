#!/usr/bin/env python3

import json
import os

from cryptojwt import KeyJar

from fedservice import create_entity_statement

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def create(iss, sub):
    kj = KeyJar()

    iss_id = "https://{}".format(iss)
    iss_jwks_file = os.path.join(BASE_PATH, iss, "{}.jwks.json".format(iss))
    kj.import_jwks_as_json(open(iss_jwks_file).read(), iss_id)

    sub_id = "https://{}".format(sub)
    sub_jwks_file = os.path.join(BASE_PATH, iss, "{}.jwks.json".format(sub))
    kj.import_jwks_as_json(open(sub_jwks_file).read(), sub_id)

    metadata_file = os.path.join(BASE_PATH, iss, "{}.metadata.json".format(sub))
    if os.path.isfile(metadata_file):
        metadata = json.loads(open(metadata_file).read())
    else:
        metadata = None

    policy_file = os.path.join(BASE_PATH, iss, "{}.policy.json".format(sub))
    if os.path.isfile(policy_file):
        policy = json.loads(open(policy_file).read())
    else:
        policy = None

    authority_file = os.path.join(BASE_PATH, iss, "{}.authority.json".format(sub))
    if os.path.isfile(authority_file):
        _auth = json.loads(open(authority_file).read())
        _jwt = create_entity_statement(iss_id, sub_id, kj, metadata, policy, _auth)
    else:
        _jwt = create_entity_statement(iss_id, sub_id, kj, metadata, policy)

    output = os.path.join(BASE_PATH, iss, sub)
    fp = open(output, "w")
    fp.write(_jwt)
    fp.close()


if __name__ == '__main__':
    for iss in os.listdir(BASE_PATH):
        path = os.path.join(BASE_PATH, iss)
        if os.path.isdir(path):
            for sub in os.listdir(path):
                if sub.endswith('.json'):
                    continue
                else:
                    create(iss, sub)
