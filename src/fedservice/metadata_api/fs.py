import json
import os
from urllib.parse import urlparse, quote_plus

from cryptojwt.key_jar import KeyJar

from fedservice.entity_statement.create import create_entity_statement
from fedservice.exception import DbFault


def mk_path(*args):
    _part = []
    for arg in args:
        if arg.startswith('https://') or arg.startswith('http://'):
            _ip = urlparse(arg)
            _part.append(format('_'.join(_ip.path[1:].split('/'))))
        else:
            _part.append(arg)
    _dir = "/".join(_part)

    if not os.path.isdir(_dir):
        return None
    else:
        return _dir


def read_metadata(sub_dir):
    return json.loads(open(os.path.join(sub_dir,
                                      'metadata.json')).read())


def get_authority_hints(base_url, sub_dir):
    roots_file = os.path.join(sub_dir, 'roots.json')
    if os.path.isfile(roots_file):
        _roots = json.loads(open(roots_file).read())
        ahint = {}
        for key, val in _roots.items():
            vals = ["{}/{}".format(base_url, v) for v in val]
            ahint["{}/{}".format(base_url, "/".join(key.split('_')))] = vals
        return {'authority_hints': ahint}
    else:
        return {}


def make_entity_statement(base_url, root_dir='.', **kwargs):
    iss = kwargs['iss']
    if iss.startswith(base_url):
        _iss_dir = mk_path(root_dir, iss)
    else:
        _iss_dir = mk_path(root_dir, quote_plus(iss))

    if not _iss_dir:
        raise DbFault('No such issuer')

    try:
        sub = kwargs['sub']
    except KeyError:
        sub = iss
        _sub_dir = _iss_dir
    else:
        if sub.startswith(base_url):
            _sub_dir = mk_path(root_dir, iss, sub)
        else:
            _sub_dir = mk_path(root_dir, iss, quote_plus(sub))

    if not _sub_dir:
        raise DbFault('Issuer do not sign for that entity')

    # Load subjects metadata
    metadata = read_metadata(_sub_dir)

    # Load issuers private signing keys
    key_jar = KeyJar()
    iss_jwks = open(os.path.join(_iss_dir, 'jwks.json')).read()
    key_jar.import_jwks_as_json(iss_jwks, iss)

    # Import subordinates signing keys from a JWKS
    if iss != sub:
        sub_jwks = open(os.path.join(_sub_dir, 'jwks.json')).read()
        key_jar.import_jwks_as_json(sub_jwks, sub)

    args = get_authority_hints(base_url, _sub_dir)

    leaf_file = os.path.join(_sub_dir, 'leaf')
    if os.path.isfile(leaf_file):
        args['sub_is_leaf'] = True

    return create_entity_statement(metadata, iss, sub, key_jar, **args)
