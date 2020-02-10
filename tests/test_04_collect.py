import os

import pytest
import requests
import responses
from cryptojwt import as_unicode
from cryptojwt.jwk import pems_to_x5c
from cryptojwt.jwk import x5c_to_pems
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from fedservice.entity_statement.create import create_entity_statement
from oidcmsg.exception import MissingPage

from fedservice.entity_statement.collect import Collector

from build.lib.fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.entity_statement.collect import branch2lists
from tests.utils import DummyCollector
from .utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'private', 'fed_keys.json')).read()

ANCHOR = {'https://feide.no': jwks}
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


def test_get_configuration_information():
    target = 'https://foodle.uninett.no'
    collector = DummyCollector(trusted_roots=ANCHOR,
                               httpd=Publisher(os.path.join(BASE_PATH, 'base_data')),
                               root_dir=os.path.join(BASE_PATH, 'base_data'))
    _jws = collector.get_configuration_information(target)
    entity_statement = verify_self_signed_signature(_jws)
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


def entity_statement_with_x5c():
    metadata = {
        "application_type": "web",
        "claims": [
            "sub",
            "name",
            "email",
            "picture"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS512"
        ],
        "redirect_uris": [
            "https://foodle.uninett.no/callback"
        ],
        "response_types": [
            "code"
        ]
    }

    iss = "https://example.com"
    sub = iss

    key_jar = build_keyjar(KEYSPEC, owner=iss)
    authority = ["https://ntnu.no"]

    with open(os.path.join(BASE_PATH, "cert.pem")) as fp:
        pems = fp.read()

    _x5c_val = pems_to_x5c([pems])
    _jws = create_entity_statement(iss, sub, key_jar, metadata=metadata, authority_hints=authority,
                                   x5c=_x5c_val)
    return _jws


def test_get_self_signed_entity_statement():
    sses = entity_statement_with_x5c()

    collector = Collector(trust_anchors=ANCHOR, http_cli=requests.request,
                          insecure=True)
    collector.ssc_dir = "."

    with responses.RequestsMock() as rsps:
        rsps.add(rsps.GET, "https://foodle.uninett.no/.well-known/openid-federation",
                 body=sses)
        # Get the self-signed entity statement from a leaf
        self_signed_statement = collector.get_configuration_information("https://foodle.uninett.no")

    _jwt = factory(self_signed_statement)
    assert _jwt

    # this should work. Not interested in the value, just that it can be done.
    msg = _jwt.jwt.payload()
    x5c_to_pems(msg["x5c"])

    # Same here
    collector.store_ssc_cert(msg, "https://foodle.uninett.no")


def test_collect_configuration():
    collector = Collector(trust_anchors=ANCHOR, http_cli=requests.request,
                          insecure=True)

    with responses.RequestsMock() as rsps:
        rsps.add(rsps.GET, "https://foodle.uninett.no/.well-known/openid-federation", status=404)
        # Get the self-signed entity statement from a leaf
        with pytest.raises(MissingPage):
            collector.get_configuration_information("https://foodle.uninett.no")
