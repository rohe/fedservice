import os

from cryptojwt import KeyJar

from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.entity_statement.verify import eval_chain
from .utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no.jwks.json')).read()

ANCHOR = {'https://feide.no': jwks}

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_eval_chains():
    target = 'https://foodle.uninett.no'
    collector = Collector(trust_anchors=ANCHOR,
                          http_cli=Publisher(os.path.join(BASE_PATH, 'base_data')))
    entity_config = collector.get_configuration_information(target)
    _config = verify_self_signed_signature(entity_config)
    assert _config

    tree = entity_config, collector.collect_superiors(target, _config)
    chains = branch2lists(tree)

    key_jar = KeyJar()
    key_jar.import_jwks_as_json(jwks, 'https://feide.no')

    statements = [eval_chain(c, key_jar, 'openid_client') for c in chains]

    assert len(statements) == 1
    statement = statements[0]
    assert statement.fo == "https://feide.no"
    assert set(statement.metadata.keys()) == {'response_types', 'claims', 'contacts',
                                              'application_type', 'redirect_uris',
                                              'id_token_signing_alg_values_supported'}
