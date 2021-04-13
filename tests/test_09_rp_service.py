import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

from cryptojwt.jws.jws import factory
from oidcrp.entity import Entity
import pytest

from fedservice import FederationEntity
from fedservice import eval_chain
from fedservice.entity_statement.collect import branch2lists
from fedservice.metadata_api.fs2 import FSEntityStatementAPI
from fedservice.rp.provider_info_discovery import FedProviderInfoDiscovery
from fedservice.rp.registration import Registration
from .utils import DummyCollector
from .utils import Publisher

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

# RECEIVER = 'https://example.org/op'

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()

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
        entity = Entity(config={
            'issuer': 'https://op.ntnu.no',
            'keys': {'key_defs': KEY_DEFS}
        })
        service_context = entity.get_service_context()

        http_cli = Publisher(os.path.join(BASE_PATH, 'base_data'))

        self.federation_entity = FederationEntity(
            entity_id,
            trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            httpd=http_cli,
            entity_type='openid_relying_party',
            opponent_entity_type='openid_provider',
            config={'keys': {'key_defs': KEY_DEFS}}
        )

        # The test data collector
        self.federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, httpd=http_cli, root_dir=os.path.join(BASE_PATH, 'base_data'))

        service_context.federation_entity = self.federation_entity
        service_context.redirect_uris = ['https://foodle.uninett.no/cb']
        # Note that the keys used for OIDC base protocol communication are separate from those used
        # in the federation context
        # service_context.keyjar = init_key_jar(key_defs=KEY_DEFS, issuer_id=entity_id)
        service_context.client_preferences = {
            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
            "id_token_signed_response_alg": "ES256",
            "token_endpoint_auth_method": "client_secret_basic",
            "federation_type": ['automatic']
        }

        self.service = {
            'discovery': FedProviderInfoDiscovery(client_get=entity.client_get),
            'registration': Registration(client_get=entity.client_get)
        }

    def test_1(self):
        _info = self.service['discovery'].get_request_parameters(iss='https://ntnu.no/op')
        assert set(_info.keys()) == {'url', 'iss'}
        p = urlparse(_info['url'])
        assert p.scheme == 'https'
        assert p.netloc == 'ntnu.no'
        assert p.path == "/.well-known/openid-federation"
        _q = parse_qs(p.query)
        assert list(_q.keys()) == ['iss']

    def test_parse_discovery_response(self):
        _dserv = self.service['discovery']
        _info = _dserv.get_request_parameters(iss='https://op.ntnu.no')
        http_response = self.federation_entity.collector.http_cli('GET', _info['url'])

        statements = _dserv.parse_response(http_response.text)
        assert len(statements) == 1
        statement = statements[0]
        assert statement.anchor == 'https://feide.no'
        _dserv.update_service_context(statements)
        assert set(_dserv.client_get("service_context").get('behaviour').keys()) == {
            'grant_types', 'id_token_signed_response_alg',
            'token_endpoint_auth_method', 'federation_type'}

    def test_create_reqistration_request(self):
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

        _sc = self.service['registration'].client_get("service_context")
        self.service['registration'].endpoint = _sc.get('provider_info')[
            'federation_registration_endpoint']

        # construct the information needed to send the request
        _info = self.service['registration'].get_request_parameters(
            request_body_type="jose", method="POST")

        assert set(_info.keys()) == {'method', 'url', 'body', 'headers', 'request'}
        assert _info['method'] == 'POST'
        assert _info['url'] == 'https://op.ntnu.no/fedreg'
        assert _info['headers'] == {'Content-Type': 'application/jose'}

        _jws = _info['body']
        _jwt = factory(_jws)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'iss', 'jwks', 'exp', 'metadata',
                                       'iat', 'sub', 'authority_hints'}
        assert set(payload['metadata']['openid_relying_party'].keys()) == {
            'application_type', "id_token_signed_response_alg", 'grant_types',
            'response_types', "token_endpoint_auth_method", 'federation_type',
            'redirect_uris'
        }

    def test_parse_registration_response(self):
        # construct the entity statement the OP should return
        es_api = FSEntityStatementAPI(os.path.join(BASE_PATH, 'base_data'), iss="op.ntnu.no")
        jws = es_api.create_entity_statement("op.ntnu.no")

        # parse the response and collect the trust chains
        res = self.service['discovery'].parse_response(jws)

        self.service['discovery'].update_service_context(res)

        _context = self.service['registration'].client_get("service_context")
        self.service['registration'].endpoint = _context.get('provider_info')[
            'federation_registration_endpoint']

        # construct the client registration request
        req_args = {'entity_id': self.federation_entity.entity_id}
        jws = self.service['registration'].construct(request_args=req_args)
        assert jws

        # construct the information needed to send the request
        _info = self.service['registration'].get_request_parameters(
            request_body_type="jose", method="POST")

        # create the request
        _req_jwt = factory(_info['body'])
        payload = _req_jwt.jwt.payload()

        # The OP as federation entity
        _fe = _context.federation_entity
        del _fe.keyjar["https://op.ntnu.no"]
        # make sure I have the private keys
        _fe.keyjar.import_jwks(
            es_api.keyjar.export_jwks(True, "https://op.ntnu.no"),
            "https://op.ntnu.no"
        )
        tree = _fe.collect_statement_chains(payload['iss'], _info['body'])
        _node = {payload['iss']: (_info['body'], tree)}
        chains = branch2lists(_node)
        statements = [eval_chain(c, _fe.keyjar, 'openid_relying_party') for c in chains]

        metadata_policy = {
            "client_id": {"value": "aaaaaaaaa"},
            "client_secret": {"value": "bbbbbbbbbb"}
        }

        # This is the registration response from the OP
        _jwt = _fe.create_entity_statement(
            'https://op.ntnu.no', 'https://foodle.uninett.no',
            metadata_policy={_fe.entity_type: metadata_policy},
            metadata={"federation_entity": {"trust_anchor_id": statements[0].anchor}},
            authority_hints=['https://feide.no'])

        claims = self.service['registration'].parse_response(_jwt, request=_info['body'])

        assert set(claims.keys()) == {
            'id_token_signed_response_alg', 'application_type', 'client_secret',
            'client_id', 'response_types', 'token_endpoint_auth_method',
            'grant_types', "contacts", 'federation_type', 'redirect_uris'}
