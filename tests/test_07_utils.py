import json
import os

from cryptojwt.key_jar import KeyJar

from fedservice.entity_statement.collect import Issuer
from fedservice.metadata_api.fs import get_authority_hints
from fedservice.metadata_api.fs import make_entity_statement
from fedservice.metadata_api.fs import mk_path
from fedservice.utils import eval_paths


BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def build_path(root_dir, base_url, iss, sub=''):
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


def test_eval_paths():
    node = build_path(os.path.join(BASE_PATH, 'fedA'), "https://127.0.0.1:6000",
                      "https://127.0.0.1:6000/com/rp")
    key_jar = load_trust_roots(os.path.join(BASE_PATH, 'trust_roots_wt.json'))
    res = eval_paths(node, key_jar, 'openid_client')
    assert set(res.keys()) == {"https://127.0.0.1:6000/fed"}
    statement = res["https://127.0.0.1:6000/fed"][0]
    claims = statement.unprotected_and_protected_claims()
    assert set(claims.keys()) == {'response_types', 'contacts', 'organization',
                                  'application_type', 'redirect_uris', 'scope',
                                  'token_endpoint_auth_method'}
