import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase
from oidcservice.state_interface import State

from fedservice import FederationEntity
from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import Issuer
from fedservice.metadata_api.fs import make_entity_statement
from fedservice.rp.service import FedProviderInfoDiscovery
from fedservice.rp.service import FedRegistrationRequest
from .utils import build_path

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

BASE_URL = 'https://127.0.0.1:6000'
ROOT_DIR = os.path.join(BASE_PATH, 'fedA')
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


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


class TestRpService(object):
    @pytest.fixture(autouse=True)
    def rp_service_setup(self):
        service_context = ServiceContext(client_id='client_id',
                                         issuer='https://127.0.0.1:6000/org/op')
        trusted_roots = json.loads(
            open(os.path.join(BASE_PATH, 'trust_roots_wt.json')).read())

        key_jar = build_keyjar(KEYSPEC, owner='abcdefghi')
        self.federation_entity = FederationEntity(key_jar=key_jar,
                                                  id='abcdefghi',
                                                  trusted_roots=trusted_roots,
                                                  authority_hints={})
        self.federation_entity.collector = DummyCollector(
            trusted_roots=trusted_roots,
            root_dir=ROOT_DIR, base_url=BASE_URL)

        service_context.federation_entity = self.federation_entity
        db = InMemoryStateDataBase()
        db.set('state', State(iss='Issuer').to_json())
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context,
                                                  state_db=db),
            'registration': FedRegistrationRequest(service_context,
                                                   state_db=db)
        }

    def test_1(self):
        _info = self.service['discovery'].get_request_parameters(
            iss='https://127.0.0.1:6000/org/op')
        assert list(_info.keys()) == ['url']
        p = urlparse(_info['url'])
        assert p.scheme == 'https'
        assert p.netloc == '127.0.0.1:6000'
        assert p.path == "/.well-known/openid-federation"
        _q = parse_qs(p.query)
        assert list(_q.keys()) == ['iss']

    def test_parse_response(self):
        _dserv = self.service['discovery']
        jws = make_entity_statement(BASE_URL, ROOT_DIR,
                                    iss='https://127.0.0.1:6000/org/op')

        res = _dserv.post_parse_response(jws)
        assert set(res.keys()) == {"https://127.0.0.1:6000/fed"}
        assert len(res["https://127.0.0.1:6000/fed"]) == 1
        _dserv.update_service_context(res)
        assert set(_dserv.service_context.behaviour.keys()) == {
            'application_type', 'response_types', 'grant_types',
            'id_token_signed_response_alg', 'token_endpoint_auth_method'}

    def test_create_request(self):
        jws = make_entity_statement(BASE_URL, ROOT_DIR,
                                    iss='https://127.0.0.1:6000/org/op')
        res = self.service['discovery'].post_parse_response(jws)
        self.service['discovery'].update_service_context(res)

        req_args = {'entity_id': self.federation_entity.id}
        jws = self.service['registration'].construct(request_args=req_args)
        assert jws

        _sc = self.service['registration'].service_context
        endp = 'https://127.0.0.1:6000/org/op/fedreg'
        _sc.provider_info['federation_registration_endpoint'] = endp
        self.service['registration'].endpoint = endp

        _info = self.service['registration'].get_request_parameters(
            request_body_type="jose", method="POST")

        assert set(_info.keys()) == {'method', 'url', 'body', 'headers'}
        assert _info['method'] == 'POST'
        assert _info['url'] == 'https://127.0.0.1:6000/org/op/fedreg'
        assert _info['headers'] == {'Content-Type': 'application/jose'}

        _jws = _info['body']
        _jwt = factory(_jws)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'iss', 'jwks', 'kid', 'exp', 'metadata',
                                       'iat', 'sub'}
        assert set(payload['metadata'].keys()) == {
            'grant_types', 'token_endpoint_auth_method', 'application_type',
            'response_types', 'id_token_signed_response_alg'}
