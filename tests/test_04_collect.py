import os

from cryptojwt.jws.jws import factory
from fedservice.entity_statement.collect import branch2lists

from build.lib.fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.entity_statement.collect import Collector

from .utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH,'private', 'fed_keys.json')).read()

ANCHOR = {'https://feide.no': jwks}


def test_get_configuration_information():
    target = 'https://foodle.uninett.no'
    collector = Collector(trust_anchors=ANCHOR,
                          http_cli=Publisher(os.path.join(BASE_PATH,'base_data')))
    entity_config = collector.get_configuration_information(target)
    _config = verify_self_signed_signature(entity_config)
    assert _config
    assert _config['iss'] == target
    assert _config['sub'] == target
    assert 'metadata' in _config


def test_get_entity_statement():
    entity_id = 'https://foodle.uninett.no'
    target = 'https://foodle.uninett.no'
    collector = Collector(trust_anchors=ANCHOR,
                          http_cli=Publisher(os.path.join(BASE_PATH,'base_data')))
    _jws = collector.get_entity_statement(api_endpoint='https://foodle.uninett.no/fed_api',
                                          issuer=entity_id, subject=target)

    msg = verify_self_signed_signature(_jws)
    assert msg['iss'] == entity_id
    assert msg['sub'] == target


def test_collect_superiors():
    # entity_id = 'https://feide.no'
    target = 'https://foodle.uninett.no'
    collector = Collector(trust_anchors=ANCHOR,
                          http_cli=Publisher(os.path.join(BASE_PATH,'base_data')))
    entity_config = collector.get_configuration_information(target)
    _config = verify_self_signed_signature(entity_config)
    assert _config

    tree = entity_config, collector.collect_superiors(target, _config)
    chains = branch2lists(tree)

    assert len(chains) == 1  # only one chain
    assert len(chains[0]) == 4  # And that chain contains 4 statements
    _jws00 = factory(chains[0][0])
    payload = _jws00.jwt.payload()
    # The Federation Entity Statement will be first in line
    assert payload["iss"] == 'https://feide.no'
