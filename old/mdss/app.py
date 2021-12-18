import json
import os

from cryptojwt import KeyJar
from flask import Flask
from flask import request

from fedservice.entity_statement.create import create_entity_statement

basedir = os.path.abspath(os.path.dirname(__file__))

ROOT_DIR = os.path.join(basedir, "data")
DOMAIN = '127.0.0.1:5000'

app = Flask(__name__)


def create(iss, sub, domain, root_dir):
    kj = KeyJar()

    if iss.startswith("https://{}/".format(domain)):
        iss_id = iss
        iss = iss[len("https://{}/".format(domain)):]
    elif iss.startswith("https://"):
        iss_id = iss
        iss = iss[len("https://")]
    else:
        iss_id = "https://{}/{}".format(domain, iss)

    iss_jwks_file = os.path.join(root_dir, iss, "{}.jwks.json".format(iss))
    kj.import_jwks_as_json(open(iss_jwks_file).read(), iss_id)

    if sub.startswith("https://{}/".format(domain)):
        sub_id = sub
        sub = sub[len("https://{}/".format(domain)):]
    elif sub.startswith("https://"):
        sub_id = sub
        sub = sub[len("https://"):]
    else:
        sub_id = "https://{}/{}".format(domain, sub)

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


@app.route('/<my_tenant_id>/.well-known/openid-federation')
def configuration(my_tenant_id):
    """
    This is using the 2nd stage of the multi-tenant handling as described in the Federation API
    section of the federation draft.

    The layout of path should therefor be: path = my-tenant-id/.well-known/openid-federation

    :param my_tenant_id:
    :return:
    """
    statement = create(my_tenant_id, my_tenant_id, DOMAIN, ROOT_DIR)
    return statement


@app.route('/<my_tenant_id>/fedapi')
def fedapi(my_tenant_id):
    """
    This is where I get if someone wants to ask someone about someone.

    :param my_tenant_id:
    :return:
    """

    if 'operation' in request.args:
        if request.args['operation'] == "fetch":
            return fetch()
    else:  # default is 'fetch'
        return fetch()


def fetch():
    iss = request.args['iss']  # required
    if 'sub' in request.args:
        statement = create(iss, request.args['sub'], DOMAIN, ROOT_DIR)
    else:
        statement = create(iss, iss, DOMAIN, ROOT_DIR)
    return statement


if __name__ == '__main__':
    ssl_context = ('certs/cert.pem', 'certs/key.pem')

    app.run(ssl_context=ssl_context)
