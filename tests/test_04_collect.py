import os

from cryptojwt.jws.jws import factory

from build.lib.fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.entity_statement.collect import branch2lists
from tests.utils import DummyCollector
from .utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'private', 'fed_keys.json')).read()

ANCHOR = {'https://feide.no': jwks}


def test_get_configuration_information():
    target = 'https://foodle.uninett.no'
    collector = DummyCollector(trusted_roots=ANCHOR,
                               httpd=Publisher(os.path.join(BASE_PATH, 'base_data')),
                               root_dir=os.path.join(BASE_PATH, 'base_data'))
    entity_statement = collector.get_configuration_information(target)
    assert entity_statement
    assert entity_statement['iss'] == target
    assert entity_statement['sub'] == target
    assert 'metadata' in entity_statement


def test_get_entity_statement():
    entity_id = 'https://foodle.uninett.no'
    target = 'https://foodle.uninett.no'
    collector = DummyCollector(trusted_roots=ANCHOR,
                               httpd=Publisher(os.path.join(BASE_PATH, 'base_data')),
                               root_dir=os.path.join(BASE_PATH, 'base_data'))
    _jws = collector.get_entity_statement(api_endpoint='https://foodle.uninett.no/fed_api',
                                          issuer=entity_id, subject=target)

    msg = verify_self_signed_signature(_jws)
    assert msg['iss'] == entity_id
    assert msg['sub'] == target


def test_collect_superiors():
    # entity_id = 'https://feide.no'
    entity_id = 'https://foodle.uninett.no'
    target = 'https://foodle.uninett.no'
    collector = DummyCollector(trusted_roots=ANCHOR,
                               httpd=Publisher(os.path.join(BASE_PATH, 'base_data')),
                               root_dir=os.path.join(BASE_PATH, 'base_data'))
    entity_statement = collector.get_entity_statement(api_endpoint='https://foodle.uninett.no/fed_api',
                                                   issuer=entity_id, subject=entity_id)
    _config = verify_self_signed_signature(entity_statement)
    assert _config

    tree = collector.collect_superiors(_config['iss'], entity_statement)
    node = {entity_id: (entity_statement , tree)}
    chains = branch2lists(node)

    assert len(chains) == 1  # only one chain
    assert len(chains[0]) == 4  # And that chain contains 4 statements
    _jws00 = factory(chains[0][0])
    payload = _jws00.jwt.payload()
    # The Federation Entity Statement will be first in line
    assert payload["iss"] == 'https://feide.no'
