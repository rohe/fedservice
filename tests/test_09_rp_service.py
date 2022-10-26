import json
import os
from urllib.parse import urlparse

from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import KeyJar
from idpyoidc.client.client_auth import PrivateKeyJWT
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.defaults import JWT_BEARER
from idpyoidc.message.oidc import AccessTokenRequest
import pytest
from idpyoidc.node import topmost_unit

from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.fetch_entity_statement.fs2 import FSFetchEntityStatement
from fedservice.fetch_entity_statement.fs2 import FSPublisher
from fedservice.rp import ClientEntity
from .build_entity import FederationEntityBuilder
from .utils import DummyCollector

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

MOD_FUNCTIONS = {
    "trust_chain_collector": {
        "class": DummyCollector,
        "kwargs": {
            'trust_anchors': ANCHOR,
            "root_dir": ROOT_DIR,
            "allowed_delta": 600
        }
    },
    'verifier': {
        'class': 'fedservice.entity.function.verifier.TrustChainVerifier',
        'kwargs': {}
    },
    'policy': {
        'class': 'fedservice.entity.function.policy.TrustChainPolicy',
        'kwargs': {}
    },
    'trust_mark_verifier': {
        'class': 'fedservice.entity.function.trust_mark_verifier.TrustMarkVerifier',
        'kwargs': {}
    }
}

FOODLE_JWKS = os.path.join(BASE_PATH, 'base_data', 'foodle.uninett.no', 'foodle.uninett.no',
                           'jwks.json')
OP_JWKS = open(os.path.join(BASE_PATH, 'base_data', 'op.ntnu.no', 'op.ntnu.no', 'jwks.json')).read()
OP_KEYJAR = KeyJar()
OP_KEYJAR.import_jwks_as_json(OP_JWKS, issuer_id='https://op.ntnu.no')
OP_KEYJAR.import_jwks_as_json(OP_JWKS, issuer_id='')

LEAF_ID = 'https://foodle.uninett.no'
OP_ID = 'https://op.ntnu.no'


class TestRpService(object):

    @pytest.fixture(autouse=True)
    def rp_service_setup(self):
        ENT = FederationEntityBuilder(
            LEAF_ID,
            metadata={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com",
                "client_registration_types": ['explicit']
            }
        )
        ENT.add_services()
        ENT.add_functions(**MOD_FUNCTIONS)
        ENT.add_endpoints(**LEAF_ENDPOINT)

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
        del oidc_service['web_finger']
        config = {
            'entity_id': LEAF_ID,
            'key_conf': {'private_path': FOODLE_JWKS},
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': ENT.conf
            },
            "openid_relying_party": {
                'class': ClientEntity,
                'kwargs': {
                    'config': {
                        'client_id': LEAF_ID,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "keys": {"uri_path": "static/jwks.json", "key_defs": KEY_DEFS},
                        "metadata": {
                            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                            "id_token_signed_response_alg": "ES256",
                            "token_endpoint_auth_method": "client_secret_basic",
                            "client_registration_types": ['automatic']
                        }
                    },
                    "services": oidc_service
                }
            },
        }

        self.entity = FederationCombo(config=config,
                                      httpc=FSPublisher(os.path.join(BASE_PATH, 'base_data')))

        self.entity['federation_entity'].function.trust_chain_collector.add_trust_anchor(
            'https://feide.no', json.loads(jwks))
        self.entity['federation_entity'].server.get_context().authority_hints = [
            'https://ntnu.no']
        self.disco_service = self.entity['openid_relying_party'].get_service('provider_info')
        self.disco_service.upstream_get("context").issuer = OP_ID
        self.registration_service = self.entity['openid_relying_party'].get_service('registration')

    def test_1(self):
        _info = self.disco_service.get_request_parameters()
        assert set(_info.keys()) == {'method', 'url', 'iss'}
        p = urlparse(_info['url'])
        assert p.scheme == 'https'
        assert p.netloc == 'op.ntnu.no'
        assert p.path == "/.well-known/openid-federation"

    def test_parse_discovery_response(self):
        _info = self.disco_service.get_request_parameters()
        http_response = self.entity.httpc('GET', _info['url'])

        statements = self.disco_service.parse_response(http_response.text)
        # there are two Trust Anchors. I only trust one.
        assert len(statements) == 1
        statement = statements[0]
        assert statement.anchor == 'https://feide.no'
        self.disco_service.update_service_context(statements)
        assert set(self.disco_service.upstream_get("context").get('behaviour').keys()) == {
            'application_type', 'response_types', 'grant_types', 'redirect_uris'}
        # 'grant_types', 'id_token_signed_response_alg',
        # 'token_endpoint_auth_method', 'federation_type'}

    def test_create_reqistration_request(self):
        # get the entity statement from the OP
        _info = self.disco_service.get_request_parameters(iss='https://op.ntnu.no')
        http_response = self.entity.httpc('GET', _info['url'])

        # parse the response and collect the trust chains
        res = self.disco_service.parse_response(http_response.text)

        self.disco_service.update_service_context(res)

        # construct the client registration request
        req_args = {'entity_id': self.entity["federation_entity"].entity_id}
        jws = self.registration_service.construct(request_args=req_args)
        assert jws

        _sc = self.registration_service.upstream_get("context")
        self.registration_service.endpoint = _sc.get('provider_info')[
            'federation_registration_endpoint']

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(
            request_body_type="jose", method="POST")

        assert set(_info.keys()) == {'method', 'url', 'body', 'headers', 'request'}
        assert _info['method'] == 'POST'
        assert _info['url'] == 'https://op.ntnu.no/fedreg'
        assert _info['headers'] == {'Content-Type': 'application/jose'}

        _jws = _info['body']
        _jwt = factory(_jws)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'trust_marks', 'sub', 'iss', 'metadata', 'jwks', 'exp',
                                       'iat', 'authority_hints'}
        assert set(payload['metadata']['openid_relying_party'].keys()) == {
            'grant_types', 'application_type', 'redirect_uris', 'response_types'}

    def test_parse_registration_response(self):
        # construct the entity statement the OP should return
        es_api = FSFetchEntityStatement(os.path.join(BASE_PATH, 'base_data'), iss="op.ntnu.no")
        jws = es_api.create_entity_statement("op.ntnu.no")

        # parse the response and collect the trust chains
        res = self.disco_service.parse_response(jws)

        _context = self.registration_service.upstream_get("context")
        _context.issuer = "https://op.ntnu.no"
        self.disco_service.update_service_context(res)

        self.registration_service.endpoint = _context.get('provider_info')[
            'federation_registration_endpoint']

        combo = topmost_unit(self.registration_service)
        _fe = combo['federation_entity']
        # construct the client registration request
        req_args = {'entity_id': _fe.context.entity_id}
        jws = self.registration_service.construct(request_args=req_args)
        assert jws

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(
            request_body_type="jose", method="POST")

        # create the request
        _req_jwt = factory(_info['body'])
        _fe.context.entity_configuration = _info['body']

        payload = _req_jwt.jwt.payload()

        # The OP as federation entity
        keyjar = combo.get_attribute('keyjar')
        # make sure I have the private keys
        keyjar.import_jwks(
            es_api.keyjar.export_jwks(True, "https://op.ntnu.no"),
            "https://op.ntnu.no"
        )

        chains, _ = collect_trust_chains(_fe, entity_id=payload['iss'],
                                         signed_entity_configuration=_info['body'])

        trust_chains = verify_trust_chains(_fe, chains, _info['body'])
        trust_chains = apply_policies(_fe, trust_chains)

        metadata_policy = {
            "client_id": {"value": "aaaaaaaaa"},
            "client_secret": {"value": "bbbbbbbbbb"}
        }

        # This is the registration response from the OP
        _jwt = _fe.context.create_entity_statement(
            'https://op.ntnu.no',
            'https://foodle.uninett.no',
            metadata_policy={'openid_relying_party': metadata_policy},
            key_jar=OP_KEYJAR,
            trust_anchor_id=trust_chains[0].anchor)

        # On the RP's side
        keyjar = self.entity['openid_relying_party'].get_attribute('keyjar')
        keyjar.import_jwks(
            es_api.keyjar.export_jwks(issuer_id="https://op.ntnu.no"),
            "https://op.ntnu.no"
        )
        claims = self.registration_service.parse_response(_jwt, request=_info['body'])

        assert set(claims.keys()) == {'application_type',
                                      'client_id',
                                      'client_secret',
                                      'contacts',
                                      'grant_types',
                                      'redirect_uris',
                                      'response_types'}


class TestRpServiceAuto(object):

    @pytest.fixture(autouse=True)
    def rp_service_setup(self):
        ENT = FederationEntityBuilder(
            LEAF_ID,
            metadata={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com",
                "client_registration_types": ['automatic']
            }
        )
        ENT.add_services()
        ENT.add_functions(**MOD_FUNCTIONS)
        ENT.add_endpoints(**LEAF_ENDPOINT)

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
        del oidc_service['web_finger']

        config = {
            'entity_id': LEAF_ID,
            'key_conf': {'private_path': FOODLE_JWKS},
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': ENT.conf
            },
            "openid_relying_party": {
                'class': ClientEntity,
                'kwargs': {
                    'config': {
                        'client_id': LEAF_ID,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "keys": {"uri_path": "static/jwks.json", "key_defs": KEY_DEFS},
                        "metadata": {
                            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                            "id_token_signed_response_alg": "ES256",
                            "token_endpoint_auth_method": "client_secret_basic",
                            "token_endpoint_auth_signing_alg": "ES256"
                        }
                    },
                    "services": oidc_service
                }
            }
        }

        self.entity = FederationCombo(config=config,
                                      httpc=FSPublisher(os.path.join(BASE_PATH, 'base_data')))

        self.entity['federation_entity'].function.trust_chain_collector.add_trust_anchor(
            'https://feide.no', json.loads(jwks))
        self.entity['federation_entity'].server.get_context().authority_hints = [
            'https://ntnu.no']

        _context = self.entity['openid_relying_party'].get_context()
        _context.provider_info = {'token_endpoint': "https://op.example.org"}

    def test_construct_client_assertion(self):
        token_service = self.entity['openid_relying_party'].get_service('accesstoken')
        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        http_args = pkj.construct(request, service=token_service, authn_endpoint='token_endpoint')

        assert http_args == {}
        _jws = factory(request["client_assertion"])
        _payload = _jws.jwt.payload()
        assert "iss" in _payload
        assert _payload["iss"] == 'https://foodle.uninett.no'
        assert _payload["sub"] == 'https://foodle.uninett.no'
        assert request['client_assertion_type'] == JWT_BEARER
