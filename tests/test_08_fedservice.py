import json
import os
from urllib.parse import parse_qs, urlparse

import pytest
from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar

from fedservice import FederationEntity
from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import Issuer
from fedservice.metadata_api.fs import make_entity_statement
from .utils import build_path

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

BASE_URL = 'https://127.0.0.1:6000'
ROOT_DIR = os.path.join(BASE_PATH, 'fedA')
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
RECEIVER = 'https://example.org/op'


class DummyCollector(Collector):
    def __init__(self, httpd=None, trusted_roots=None, root_dir='.',
                 base_url=''):
        Collector.__init__(self, httpd, trusted_roots=trusted_roots)
        self.root_dir = root_dir
        self.base_url = base_url

    def collect_entity_statements(self, response):
        _jwt = factory(response)
        if _jwt:
            entity_statement = _jwt.jwt.payload()
        else:
            return None

        node = Issuer(response)

        for authority, roots in entity_statement['authority_hints'].items():
            node.superior.append(
                build_path(self.root_dir, self.base_url, authority,
                           sub=entity_statement['iss']))

        return node


class MockResponse():
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class Publisher(object):
    def __init__(self, directory):
        self.dir = directory

    def __call__(self, method, url, **kwargs):
        p = urlparse(url)
        _qs = parse_qs(p.query)
        pt = urlparse(_qs['sub'][0])
        _jws = open(os.path.join(self.dir, p.netloc, pt.netloc)).read().strip()

        return MockResponse(200, '["{}"]'.format(_jws),
                            headers={'content-type': "application/jws"})


class TestRpService(object):
    @pytest.fixture(autouse=True)
    def rp_service_setup(self):
        trusted_roots = json.loads(
            open(os.path.join(BASE_PATH, 'trust_roots_wt.json')).read())

        federation_entity = FederationEntity(
            'https://127.0.0.1:6000/org/rp', trusted_roots=trusted_roots,
            authority_hints={},
            httpd=Publisher(os.path.join(BASE_PATH, 'data')),
            entity_type='openid_client', opponent_entity_type='openid_provider'
        )

        federation_entity.collector = DummyCollector(
            httpd=Publisher(os.path.join(BASE_PATH, 'data')),
            trusted_roots=trusted_roots,
            root_dir=ROOT_DIR, base_url=BASE_URL)

        self.fedent = federation_entity

    def test_load_entity_statement(self):
        entity_id = 'https://foodle.uninett.no'
        target = 'https://foodle.uninett.no'
        _jws = self.fedent.load_entity_statements(entity_id, target)
        _jwt = factory(_jws[0])

        assert _jwt
        msg = json.loads(as_unicode(_jwt.jwt.part[1]))
        assert msg['iss'] == entity_id
        assert msg['sub'] == target

    def test_collect_entity_statement(self):
        jws = make_entity_statement(BASE_URL, ROOT_DIR,
                                    iss='https://127.0.0.1:6000/org/op')
        _node = self.fedent.collect_entity_statements(jws)
        assert isinstance(_node, Issuer)

    def test_create_entity_statement(self):
        entity_id = 'https://foodle.uninett.no'
        target = 'https://foodle.uninett.no'
        _jws = self.fedent.load_entity_statements(entity_id, target)
        _jwt = factory(_jws[0])

        assert _jwt
        msg = json.loads(as_unicode(_jwt.jwt.part[1]))
        assert msg['iss'] == entity_id
        assert msg['sub'] == target

    def test_eval_path(self):
        jws = make_entity_statement(BASE_URL, ROOT_DIR,
                                    iss='https://127.0.0.1:6000/org/op')
        _node = self.fedent.collect_entity_statements(jws)
        res = self.fedent.eval_paths(_node)
        assert list(res.keys()) == ['https://127.0.0.1:6000/fed']
        statement = res['https://127.0.0.1:6000/fed'][0]
        claims = statement.claims()
        assert set(claims.keys()) == {'token_endpoint', 'organization',
                                      'id_token_signing_alg_values_supported',
                                      'authorization_endpoint',
                                      'userinfo_endpoint'}

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

        key_jar = build_keyjar(KEYSPEC, owner=iss)
        authority = {"https://ntnu.no": ["https://feide.no"]}

        _jwt = self.fedent.create_entity_statement(metadata, iss, sub, key_jar,
                                                   authority)

        assert _jwt

        _verifier = factory(_jwt)
        keys = key_jar.get_jwt_verify_keys(_verifier.jwt)
        res = _verifier.verify_compact(keys=keys)

        assert res
        assert res['iss'] == iss
        assert res['sub'] == sub
        assert set(res.keys()) == {'metadata', 'iss', 'exp', 'sub', 'iat',
                                   'authority_hints', 'jwks', 'kid'}
