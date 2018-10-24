import os

from fedservice.utils import eval_paths

from .utils import build_path
from .utils import load_trust_roots

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_eval_paths():
    node = build_path(os.path.join(BASE_PATH, 'fedA'), "https://127.0.0.1:6000",
                      "https://127.0.0.1:6000/com/rp")
    key_jar = load_trust_roots(os.path.join(BASE_PATH, 'trust_roots_wt.json'))

    res = eval_paths(node, key_jar, 'openid_client')

    assert set(res.keys()) == {"https://127.0.0.1:6000/fed"}

    statement = res["https://127.0.0.1:6000/fed"][0]
    claims = statement.claims()
    assert set(claims.keys()) == {'response_types', 'contacts', 'organization',
                                  'application_type', 'redirect_uris', 'scope',
                                  'token_endpoint_auth_method'}
