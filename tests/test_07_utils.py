import os

from cryptojwt import KeyJar

from fedservice.entity.function import tree2chains
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.node import Node
from tests.utils import DummyCollector
from .utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()

ANCHOR = {'https://feide.no': jwks}

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_eval_chains():
    target = 'https://foodle.uninett.no'
    collector = DummyCollector(trusted_roots=ANCHOR,
                               httpd=Publisher(os.path.join(BASE_PATH, 'base_data')),
                               root_dir=os.path.join(BASE_PATH, 'base_data'))
    entity_statement = collector.get_entity_statement(target,
                                                      issuer=target,
                                                      subject=target)
    _config = verify_self_signed_signature(entity_statement)
    assert _config

    tree = collector.collect_superiors(_config['iss'], entity_statement)
    _node = {target: (entity_statement, tree)}
    chains = tree2chains(_node)

    key_jar = KeyJar()
    key_jar.import_jwks_as_json(jwks, 'https://feide.no')

    _node = Node(keyjar=key_jar)
    _verifier = TrustChainVerifier(superior_get=_node.get_node)

    statements = _verifier(chains)

    assert len(statements) == 1
    statement = statements[0]
    assert statement.anchor == "https://feide.no"
    assert set(statement.metadata.keys()) == {
        'response_types', 'claims', 'contacts', 'application_type', 'redirect_uris',
        'id_token_signing_alg_values_supported', 'jwks_uri'}
