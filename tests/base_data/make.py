#!/usr/bin/env python3

import os

from fedservice.fetch_entity_statement.fs2 import FSEntityStatementAPI

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def make_entity_id(item):
    return "https://{}".format(item)


for iss in os.listdir(BASE_PATH):
    path = os.path.join(BASE_PATH, iss)
    if os.path.isdir(path):
        fse = FSEntityStatementAPI(BASE_PATH, iss=iss)
        # fse.make_entity_id = make_entity_id
        fse.load_jwks(iss, iss, make_entity_id(iss))
        for sub in os.listdir(path):
            sub_path = os.path.join(path, sub)
            if os.path.isdir(sub_path):
                _jwt = fse.create_entity_statement(sub)
                output = os.path.join(BASE_PATH, iss, sub, 'jws')
                fp = open(output, "w")
                fp.write(_jwt)
                fp.close()
