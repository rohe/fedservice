import json

from cryptojwt.key_jar import KeyJar

from fedservice.entity_statement.collect import Issuer

from fedservice.metadata_api.fs import get_authority_hints
from fedservice.metadata_api.fs import make_entity_statement
from fedservice.metadata_api.fs import mk_path


def build_path(root_dir, base_url, iss, sub=''):
    """
    Builds a trust path as a sequence of signed JWTs containing entity
    statements

    :param root_dir: Where to find the dummy information to put in the entity
        statement
    :param base_url: The base URL or the metadata API service
    :param iss: Which issuer to use
    :param sub: The identifier of the subject
    :return: An Issuer instance
    """
    jws = make_entity_statement(base_url, root_dir, iss=iss, sub=sub)
    node = Issuer(jws)

    if not sub:
        _dir = mk_path(root_dir, iss)
    else:
        _dir = mk_path(root_dir, iss, sub)
    ah = get_authority_hints(base_url, _dir)
    if ah:
        for key, sups in ah['authority_hints'].items():
            node.superior.append(build_path(root_dir, base_url, key, iss))

    return node


def load_trust_roots(trust_root_file):
    trust_roots = json.loads(open(trust_root_file).read())
    kj = KeyJar()
    for iss, jwks in trust_roots.items():
        kj.import_jwks(jwks, iss)
    return kj
