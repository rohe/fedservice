import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import KeyJar, build_keyjar
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase
from oidcservice.state_interface import State

from fedservice import FederationEntity
from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import Issuer
from fedservice.metadata_api.fs import make_entity_statement
from fedservice.rp.provider_info_discovery import FedProviderInfoDiscovery
from fedservice.rp.registration import FedRegistration
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
        entity_id = 'https://127.0.0.1:6000/org/rp'
        service_context = ServiceContext(issuer=entity_id)
        trusted_roots = json.loads(
            open(os.path.join(BASE_PATH, 'trust_roots_wt.json')).read())

        key_jar = build_keyjar(KEYSPEC, owner=entity_id)
        self.federation_entity = FederationEntity(
            key_jar=key_jar, entity_id=entity_id, trusted_roots=trusted_roots,
            authority_hints={
                'https://127.0.0.1:6000/org/a': ['https://127.0.0.1:6000/fed']
            },
            entity_type='openid_client', opponent_entity_type='openid_provider'
        )

        self.federation_entity.collector = DummyCollector(
            trusted_roots=trusted_roots,
            root_dir=ROOT_DIR, base_url=BASE_URL)

        service_context.federation_entity = self.federation_entity
        db = InMemoryStateDataBase()
        db.set('state', State(iss='Issuer').to_json())
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context,
                                                  state_db=db),
            'registration': FedRegistration(service_context,
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

        res = _dserv.parse_response(jws)
        assert set(res.keys()) == {"https://127.0.0.1:6000/fed"}
        assert len(res["https://127.0.0.1:6000/fed"]) == 1
        _dserv.update_service_context(res)
        assert set(_dserv.service_context.behaviour.keys()) == {
            'grant_types', 'id_token_signed_response_alg',
            'token_endpoint_auth_method'}

    def test_create_request(self):
        # construct the entity statement the OP should return
        jws = make_entity_statement(BASE_URL, ROOT_DIR,
                                    iss='https://127.0.0.1:6000/org/op')
        # parse the response and collect the trust chains
        res = self.service['discovery'].parse_response(jws)

        self.service['discovery'].update_service_context(res)

        # construct the client registration request
        req_args = {'entity_id': self.federation_entity.entity_id}
        jws = self.service['registration'].construct(request_args=req_args)
        assert jws

        _sc = self.service['registration'].service_context
        endp = 'https://127.0.0.1:6000/org/op/fedreg'
        _sc.provider_info['federation_registration_endpoint'] = endp
        self.service['registration'].endpoint = endp

        # construct the information needed to send the request
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
                                       'iat', 'sub', 'authority_hints'}
        assert set(payload['metadata']['openid_client'].keys()) == {
            'grant_types', 'token_endpoint_auth_method', 'application_type',
            'response_types', 'id_token_signed_response_alg'}

    def test_parse_reg_response(self):
        # construct the entity statement the OP should return
        jws = make_entity_statement(BASE_URL, ROOT_DIR,
                                    iss='https://127.0.0.1:6000/org/op')
        # parse the response and collect the trust chains
        res = self.service['discovery'].parse_response(jws)

        self.service['discovery'].update_service_context(res)

        _sc = self.service['registration'].service_context
        endp = 'https://127.0.0.1:6000/org/op/fedreg'
        _sc.provider_info['federation_registration_endpoint'] = endp
        self.service['registration'].endpoint = endp

        # construct the client registration request
        req_args = {'entity_id': self.federation_entity.entity_id}
        jws = self.service['registration'].construct(request_args=req_args)
        assert jws

        # construct the information needed to send the request
        _info = self.service['registration'].get_request_parameters(
            request_body_type="jose", method="POST")

        _jwt = factory(_info['body'])
        payload = _jwt.jwt.payload()

        _md = payload['metadata']['openid_client']
        _md.update({'client_id': 'aaaaaaaaa', 'client_secret': 'bbbbbbbbbb'})
        _fe = _sc.federation_entity
        key_jar = KeyJar()
        key_jar.import_jwks_as_json(
            open(os.path.join(ROOT_DIR, 'org_op', 'jwks.json')).read(),
            'https://127.0.0.1:6000/org/op'
        )
        _jwt = _fe.create_entity_statement(
            {_fe.entity_type: _md}, 'https://127.0.0.1:6000/org/op',
            'https://127.0.0.1:6000/org/rp', key_jar,
            authority_hints={
                'https://127.0.0.1:6000/org/b': [
                    'https://127.0.0.1:6000/org/op/fedreg']
            }, include_jwks=False)

        claims = self.service['registration'].parse_response(_jwt)
        assert set(claims.keys()) == {
            'id_token_signed_response_alg', 'application_type', 'client_secret',
            'client_id', 'response_types', 'token_endpoint_auth_method',
            'grant_types'}
