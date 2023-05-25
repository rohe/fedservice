import json
import os

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar

from fedservice.entity.function import tree2chains
from tests.utils import DummyCollector

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

# RECEIVER = 'https://example.org/op'

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()

ANCHOR = {'https://feide.no': json.loads(jwks)}


class TestDummyCollector:

    @pytest.fixture(autouse=True)
    def create_collector(self):
        self.collector = DummyCollector(ANCHOR, None,
                                        root_dir=os.path.join(BASE_PATH, 'base_data'),
                                        keyjar=init_key_jar(key_defs=KEYSPEC)
                                        )

    def test_get_entity_configuration(self):
        _configuration = self.collector.get_entity_configuration('https://feide.no')
        assert _configuration
        _jws = factory(_configuration)
        payload = _jws.jwt.payload()
        assert payload['iss'] == 'https://feide.no'
        assert payload['sub'] == 'https://feide.no'
        assert payload['metadata']["federation_entity"][
                   "federation_fetch_endpoint"] == "https://feide.no/fetch"

    def test_get_entity_statement(self):
        _statement = self.collector.get_entity_statement("https://feide.no/fetch",
                                                         issuer='https://feide.no',
                                                         subject='https://ntnu.no')

        assert _statement
        _jws = factory(_statement)
        payload = _jws.jwt.payload()
        assert payload['iss'] == 'https://feide.no'
        assert payload['sub'] == 'https://ntnu.no'

    def test_collect(self):
        _tree, _selfsigned = self.collector('https://foodle.uninett.no')
        assert _tree
        _chains = tree2chains(_tree)
        assert len(_chains) == 2
