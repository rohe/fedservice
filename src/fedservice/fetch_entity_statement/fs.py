import json
import logging
import os
from urllib.parse import urlparse

from cryptojwt.key_jar import KeyJar

from fedservice.entity_statement.create import create_entity_statement

logger = logging.getLogger(__name__)


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


def read_info(dir, sub, typ='metadata'):
    file_name = os.path.join(dir, "{}.{}.json".format(sub, typ))
    if os.path.isfile(file_name):
        return json.loads(open(file_name).read())
    else:
        return None


def get_authority_hints(iss, sub, root_dir):
    _auth = read_info(os.path.join(root_dir, iss), sub, "authority")
    if _auth:
        return _auth
    else:
        return {}


def make_entity_statement(iss, root_dir='.', sub=""):
    kj = KeyJar()

    if iss.startswith('https://'):
        iss_id = iss
        iss = iss[len("https://"):]
    else:
        iss_id = "https://{}".format(iss)

    _jwks = read_info(os.path.join(root_dir, iss), iss, "jwks")
    kj.import_jwks(_jwks, iss_id)

    if not sub:
        sub = iss

    if sub.startswith('https://'):
        sub_id = sub
        sub = sub[len("https://"):]
    else:
        sub_id = "https://{}".format(sub)

    _jwks = read_info(os.path.join(root_dir, iss), sub, "jwks")
    kj.import_jwks(_jwks, sub_id)

    metadata = read_info(os.path.join(root_dir, iss), sub, "metadata")
    policy = read_info(os.path.join(root_dir, iss), sub, "policy")

    _auth = get_authority_hints(iss, sub, root_dir)
    if _auth:
        _jwt = create_entity_statement(iss_id, sub_id, kj, metadata, policy, _auth)
    else:
        _jwt = create_entity_statement(iss_id, sub_id, kj, metadata, policy)

    return _jwt
