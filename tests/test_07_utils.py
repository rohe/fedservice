import os

from cryptojwt import KeyJar

from fedservice.entity.function import tree2chains
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.fetch_entity_statement.fs2 import FSPublisher
from fedservice.node import Unit
from tests.utils import DummyCollector

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()

ANCHOR = {'https://feide.no': jwks}

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_eval_chains():
    target = 'https://foodle.uninett.no'
    collector = DummyCollector(trusted_roots=ANCHOR,
                               httpd=FSPublisher(os.path.join(BASE_PATH, 'base_data')),
                               root_dir=os.path.join(BASE_PATH, 'base_data')
                               )
    entity_configuration = collector.get_entity_statement(target,
                                                      issuer=target,
                                                      subject=target)
    _config = verify_self_signed_signature(entity_configuration)
    assert _config

    tree = collector.collect_tree(_config['iss'], entity_configuration)
    _unit = {target: (entity_configuration, tree)}
    chains = tree2chains(_unit)

    key_jar = KeyJar()
    key_jar.import_jwks_as_json(jwks, 'https://feide.no')

    _unit = Unit(keyjar=key_jar)
    _verifier = TrustChainVerifier(upstream_get=_unit.get_unit)

    statements = _verifier(chains)

    assert len(statements) == 1
    statement = statements[0]
    assert statement.anchor == "https://feide.no"
    assert set(statement.metadata.keys()) == {
        'response_types', 'claims', 'contacts', 'application_type', 'redirect_uris',
        'id_token_signing_alg_values_supported', 'jwks_uri'}
