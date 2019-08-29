import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import init_key_jar
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase
from oidcservice.state_interface import State

from fedservice import FederationEntity
from fedservice.metadata_api.fs import make_entity_statement
from fedservice.metadata_api.fs import read_info
from fedservice.rp.provider_info_discovery import FedProviderInfoDiscovery
from fedservice.rp.registration import FedRegistration
from .utils import DummyCollector
from .utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

# RECEIVER = 'https://example.org/op'

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no.jwks.json')).read()

ANCHOR = {'https://feide.no': json.loads(jwks)}

KEY_DEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]}
]


class TestRpService(object):
    @pytest.fixture(autouse=True)
    def rp_service_setup(self):
        entity_id = 'https://foodle.uninett.no'
        service_context = ServiceContext(issuer=entity_id)

        http_cli = Publisher(os.path.join(BASE_PATH, 'base_data'))

        self.federation_entity = FederationEntity(
            entity_id,
            trusted_roots=ANCHOR,
            authority_hints={'https://ntnu.no': ['https://feide.no']},
            httpd=http_cli,
            entity_type='openid_client',
            opponent_entity_type='openid_provider',
            key_jar=init_key_jar(key_defs=KEY_DEFS, owner=entity_id)
        )

        # The test data collector
        self.federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, httpd=http_cli, root_dir=os.path.join(BASE_PATH, 'base_data'))

        service_context.federation_entity = self.federation_entity
        service_context.redirect_uris = ['https://foodle.uninett.no/cb']
        # Note that the keys used for OIDC base protocol communication are separate from those used
        # in the federation context
        service_context.keyjar = init_key_jar(key_defs=KEY_DEFS, owner=entity_id)
        service_context.client_preferences = {
            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
            "id_token_signed_response_alg": "ES256",
            "token_endpoint_auth_method": "client_secret_basic"
        }

        db = InMemoryStateDataBase()
        db.set('state', State(iss='Issuer').to_json())
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context,
                                                  state_db=db),
            'registration': FedRegistration(service_context,
                                            state_db=db)
        }

    def test_1(self):
        _info = self.service['discovery'].get_request_parameters(iss='https://ntnu.no/op')
        assert list(_info.keys()) == ['url']
        p = urlparse(_info['url'])
        assert p.scheme == 'https'
        assert p.netloc == 'ntnu.no'
        assert p.path == "/.well-known/openid-federation"
        _q = parse_qs(p.query)
        assert list(_q.keys()) == ['iss']

    def test_parse_response(self):
        _dserv = self.service['discovery']
        _info = _dserv.get_request_parameters(iss='https://op.ntnu.no')
        http_response = self.federation_entity.collector.http_cli('GET', _info['url'])

        statements = _dserv.parse_response(http_response.text)
        assert len(statements) == 1
        statement = statements[0]
        assert statement.fo == 'https://feide.no'
        _dserv.update_service_context(statements)
        assert set(_dserv.service_context.behaviour.keys()) == {
            'grant_types', 'id_token_signed_response_alg',
            'token_endpoint_auth_method'}

    def test_create_request(self):
        # get the entity statement from the OP
        _dserv = self.service['discovery']
        _info = _dserv.get_request_parameters(iss='https://op.ntnu.no')
        http_response = self.federation_entity.collector.http_cli('GET', _info['url'])

        # parse the response and collect the trust chains
        res = self.service['discovery'].parse_response(http_response.text)

        self.service['discovery'].update_service_context(res)

        # construct the client registration request
        req_args = {'entity_id': self.federation_entity.entity_id}
        jws = self.service['registration'].construct(request_args=req_args)
        assert jws

        _sc = self.service['registration'].service_context
        self.service['registration'].endpoint = _sc.provider_info[
            'federation_registration_endpoint']

        # construct the information needed to send the request
        _info = self.service['registration'].get_request_parameters(
            request_body_type="jose", method="POST")

        assert set(_info.keys()) == {'method', 'url', 'body', 'headers'}
        assert _info['method'] == 'POST'
        assert _info['url'] == 'https://op.ntnu.no/fedreg'
        assert _info['headers'] == {'Content-Type': 'application/jose'}

        _jws = _info['body']
        _jwt = factory(_jws)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'iss', 'jwks', 'kid', 'exp', 'metadata',
                                       'iat', 'sub', 'authority_hints'}
        assert set(payload['metadata']['openid_client'].keys()) == {
            'application_type', "id_token_signed_response_alg", 'redirect_uris', 'grant_types',
            'response_types', "token_endpoint_auth_method"}

    def test_parse_reg_response(self):
        # construct the entity statement the OP should return
        jws = make_entity_statement('https://op.ntnu.no',
                                    root_dir=os.path.join(BASE_PATH, 'base_data'))
        # parse the response and collect the trust chains
        res = self.service['discovery'].parse_response(jws)

        self.service['discovery'].update_service_context(res)

        _sc = self.service['registration'].service_context
        self.service['registration'].endpoint = _sc.provider_info[
            'federation_registration_endpoint']

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
        # The OP as federation entity
        _fe = _sc.federation_entity
        del _fe.key_jar.issuer_keys["https://op.ntnu.no"]
        _fe.key_jar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), "op.ntnu.no", "jwks"),
            "https://op.ntnu.no"
        )
        _jwt = _fe.create_entity_statement(
            'https://op.ntnu.no', 'https://foodle.uninett.no',
            metadata={_fe.entity_type: _md},
            authority_hints={'https://feide.no': ['https://feide.no']})

        claims = self.service['registration'].parse_response(_jwt)
        assert set(claims.keys()) == {
            'id_token_signed_response_alg', 'application_type', 'client_secret',
            'client_id', 'response_types', 'token_endpoint_auth_method',
            'grant_types', 'redirect_uris'}
