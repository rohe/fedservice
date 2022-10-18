import json
import os

from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
import pytest

from fedservice.entity import FederationEntity
from fedservice.entity.fetch import Fetch
from fedservice.entity_statement.collect import tree2chains
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.entity.function.verifier import eval_chain
from tests.utils import DummyCollector
from .utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

BASE_URL = 'https://127.0.0.1:6000'
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
RECEIVER = 'https://example.org/op'

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()

ANCHOR = {'https://feide.no': json.loads(jwks)}


class TestRpService(object):
    @pytest.fixture(autouse=True)
    def rp_service_setup(self):
        config = {
            "entity_id": RECEIVER,
            "httpc_params": {"verify": False, "timeout": 1},
            "federation": {
                "endpoint": {
                    "fetch": {
                        "path": "fetch",
                        "class": Fetch,
                        "kwargs": {"client_authn_method": None},
                    }
                },
                "trusted_roots": ANCHOR,
                "authority_hints": [],
                "entity_type": 'openid_relying_party',
                "opponent_entity_type": 'openid_provider',
            }
        }
        federation_entity = FederationEntity(
            config=config,
            httpc=Publisher(os.path.join(BASE_PATH, 'base_data')),
        )
        # Swap in the DummyCollector
        federation_entity.collector = DummyCollector(trusted_roots=ANCHOR,
                                                     httpd=Publisher(
                                                         os.path.join(BASE_PATH, 'base_data')),
                                                     root_dir=os.path.join(BASE_PATH, 'base_data'))
        self.fedent = federation_entity

    def test_get_configuration_information(self):
        entity_id = 'https://foodle.uninett.no'
        _jws = self.fedent.get_configuration_information(entity_id)
        msg = verify_self_signed_signature(_jws)
        assert msg['iss'] == entity_id

    def test_load_entity_statement(self):
        entity_id = 'https://foodle.uninett.no'
        target = 'https://foodle.uninett.no'
        _jws = self.fedent.collector.get_entity_statement('https://foodle.uninett.no/api',
                                                          entity_id, target)
        _jwt = factory(_jws)

        assert _jwt
        msg = _jwt.jwt.payload()
        assert msg['iss'] == entity_id
        assert msg['sub'] == target

    def test_collect_entity_statement(self):
        leaf_entity_id = 'https://foodle.uninett.no'
        entity_statement = self.fedent.collector.get_entity_statement('', leaf_entity_id,
                                                                      leaf_entity_id)
        tree = self.fedent.collect_statement_chains(leaf_entity_id, entity_statement)
        assert tree
        _Unit = {leaf_entity_id: (entity_statement, tree)}
        chains = tree2chains(_Unit)
        assert len(chains) == 1
        assert len(chains[0]) == 4

    def test_eval_path(self):
        leaf_entity_id = 'https://foodle.uninett.no'
        _jws = self.fedent.collector.get_entity_statement('', leaf_entity_id, leaf_entity_id)
        tree = self.fedent.collect_statement_chains(leaf_entity_id, _jws)
        _Unit = {leaf_entity_id: (_jws, tree)}
        chains = tree2chains(_Unit)
        statements = [
            eval_chain(c, self.fedent.endpoint_context.federation.keyjar, 'openid_relying_party')
            for c in chains]
        assert len(statements) == 1
        statement = statements[0]
        assert set(statement.metadata.keys()) == {'application_type', 'claims',
                                                  'id_token_signing_alg_values_supported',
                                                  'redirect_uris', 'contacts', 'response_types',
                                                  'jwks_uri'}
        statement = self.fedent.pick_trust_chain(statements)
        assert statement.anchor == 'https://feide.no'
        assert set(statement.metadata.keys()) == {'application_type', 'claims',
                                                  'id_token_signing_alg_values_supported',
                                                  'redirect_uris', 'contacts', 'response_types',
                                                  'jwks_uri'}

    def test_create_self_signed(self):
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

        key_jar = build_keyjar(KEYSPEC, issuer_id=iss)
        authority = {"https://ntnu.no": ["https://feide.no"]}

        _jwt = self.fedent.endpoint_context.federation.create_entity_statement(
            iss, sub, key_jar=key_jar, metadata=metadata, authority_hints=authority)

        assert _jwt

        _verifier = factory(_jwt)
        keys = key_jar.get_jwt_verify_keys(_verifier.jwt)
        res = _verifier.verify_compact(keys=keys)

        assert res
        assert res['iss'] == iss
        assert res['sub'] == sub
        assert set(res.keys()) == {'metadata', 'iss', 'exp', 'sub', 'iat',
                                   'authority_hints', 'jwks'}
