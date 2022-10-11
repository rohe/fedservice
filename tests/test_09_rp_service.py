import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

from cryptojwt.jws.jws import factory
from idpyoidc.client.client_auth import PrivateKeyJWT
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.oidc import RP
from idpyoidc.defaults import JWT_BEARER
from idpyoidc.message.oidc import AccessTokenRequest
import pytest

from build.lib.fedservice.trust_mark_issuer.status import Status
from fedservice.combo import Combo
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.entity import FederationEntity
from fedservice.entity.client import FederationEntityClient
from fedservice.entity.client.entity_configuration import \
    EntityConfiguration as c_EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement
from fedservice.entity.function import tree2chains
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.entity_configuration import EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.fetch_entity_statement.fs2 import FSFetchEntityStatement
from fedservice.node import Collection
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
        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
        entity_id = 'https://foodle.uninett.no'
        config = {
            "keys": {"key_defs": KEY_DEFS},
            "federation_entity": {
                'class': FederationEntity,
                "function": {
                    'class': Collection,
                    'kwargs': {
                        'functions': {
                            "trust_chain_collector": {
                                "class": TrustChainCollector,
                                "kwargs": {
                                    # "trust_anchors": ANCHOR,
                                    "allowed_delta": 600
                                }
                            },
                            'verifier': {
                                'class': TrustChainVerifier,
                                'kwargs': {}
                            },
                            'policy': {
                                'class': TrustChainPolicy,
                                'kwargs': {}
                            }
                        }
                    }
                },
                "client": {
                    'class': FederationEntityClient,
                    'kwargs': {
                        "services": {
                            "entity_configuration": {
                                "class": c_EntityConfiguration,
                                "kwargs": {}
                            },
                            "entity_statement": {
                                "class": EntityStatement,
                                "kwargs": {}
                            }
                        }
                    }
                },
                "server": {
                    'class': FederationEntityServer,
                    'kwargs': {
                        "metadata": {
                            # "authority_hints": [TA_ID],
                            # "organization_name": "The example",
                            # "homepage_uri": "https://www.example.com",
                            # "contacts": "app@rp.example.com"
                        },
                        "endpoint": {
                            "entity_configuration": {
                                "path": ".well-known/openid-federation",
                                "class": EntityConfiguration,
                                "kwargs": {}
                            }
                        }
                    }
                }
            },
            "openid_relying_party": {
                'class': RP,
                'kwargs': {
                    'client_id': entity_id,
                    'client_secret': 'a longesh password',
                    'redirect_uris': ['https://example.com/cli/authz_cb'],
                    "keys": {"uri_path": "static/jwks.json", "key_defs": KEY_DEFS},
                    "metadata": {
                        "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                        "id_token_signed_response_alg": "ES256",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "client_registration_types": ['automatic']
                    },
                    "services": oidc_service
                }
            },
            "trust_mark_issuer": {
                'class': "TrustMarkIssuer",
                'kwargs': {
                    "endpoint": {
                        "status": {
                            "path": "status",
                            "class": Status,
                            "kwargs": {"client_authn_method": None},
                        }
                    }
                }
            }
        }

        self.entity = Combo(config=config)

        httpc = Publisher(os.path.join(BASE_PATH, 'base_data'))

        _context = self.entity.superior_get("service_context")
        # The test data collector
        _context.federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, httpd=httpc, root_dir=os.path.join(BASE_PATH, 'base_data'))

        self.disco_service = self.entity.superior_get("service", 'provider_info')
        self.registration_service = self.entity.superior_get("service", 'registration')

    def test_1(self):
        _info = self.disco_service.get_request_parameters(iss='https://ntnu.no/op')
        assert set(_info.keys()) == {'url', 'iss'}
        p = urlparse(_info['url'])
        assert p.scheme == 'https'
        assert p.netloc == 'ntnu.no'
        assert p.path == "/.well-known/openid-federation"
        _q = parse_qs(p.query)
        assert list(_q.keys()) == ['iss']

    def test_parse_discovery_response(self):
        _context = self.entity.superior_get("service_context")
        _info = self.disco_service.get_request_parameters(iss='https://op.ntnu.no')
        http_response = _context.federation_entity.collector.http_cli('GET', _info['url'])

        statements = self.disco_service.parse_response(http_response.text)
        assert len(statements) == 1
        statement = statements[0]
        assert statement.anchor == 'https://feide.no'
        self.disco_service.update_service_context(statements)
        assert set(self.disco_service.superior_get("service_context").get('behaviour').keys()) == {
            'grant_types', 'id_token_signed_response_alg',
            'token_endpoint_auth_method', 'federation_type'}

    def test_create_reqistration_request(self):
        # get the entity statement from the OP
        _info = self.disco_service.get_request_parameters(iss='https://op.ntnu.no')
        _context = self.entity.superior_get("service_context")
        http_response = _context.federation_entity.collector.http_cli('GET', _info['url'])

        # parse the response and collect the trust chains
        res = self.disco_service.parse_response(http_response.text)

        self.disco_service.update_service_context(res)

        # construct the client registration request
        req_args = {'entity_id': _context.federation_entity.context.entity_id}
        jws = self.registration_service.construct(request_args=req_args)
        assert jws

        _sc = self.registration_service.superior_get("service_context")
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
        assert set(payload.keys()) == {'iss', 'jwks', 'exp', 'metadata',
                                       'iat', 'sub', 'authority_hints'}
        assert set(payload['metadata']['openid_relying_party'].keys()) == {
            'application_type', "id_token_signed_response_alg", 'grant_types',
            'response_types', "token_endpoint_auth_method", 'federation_type',
            'redirect_uris'
        }

    def test_parse_registration_response(self):
        # construct the entity statement the OP should return
        es_api = FSFetchEntityStatement(os.path.join(BASE_PATH, 'base_data'), iss="op.ntnu.no")
        jws = es_api.create_entity_statement("op.ntnu.no")

        # parse the response and collect the trust chains
        res = self.disco_service.parse_response(jws)

        _context = self.registration_service.superior_get("service_context")
        _fe = _context.federation_entity
        _context.issuer = "https://op.ntnu.no"
        self.disco_service.update_service_context(res)

        self.registration_service.endpoint = _context.get('provider_info')[
            'federation_registration_endpoint']

        # construct the client registration request
        req_args = {'entity_id': _fe.context.entity_id}
        jws = self.registration_service.construct(request_args=req_args)
        assert jws

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(
            request_body_type="jose", method="POST")

        # create the request
        _req_jwt = factory(_info['body'])
        payload = _req_jwt.jwt.payload()

        # The OP as federation entity
        del _fe.context.keyjar["https://op.ntnu.no"]
        # make sure I have the private keys
        _fe.context.keyjar.import_jwks(
            es_api.keyjar.export_jwks(True, "https://op.ntnu.no"),
            "https://op.ntnu.no"
        )
        tree = _fe.collect_statement_chains(payload['iss'], _info['body'])
        _node = {payload['iss']: (_info['body'], tree)}
        chains = tree2chains(_node)
        statements = [eval_chain(c, _fe.context.keyjar, 'openid_relying_party') for c in chains]

        metadata_policy = {
            "client_id": {"value": "aaaaaaaaa"},
            "client_secret": {"value": "bbbbbbbbbb"}
        }

        # This is the registration response from the OP
        _jwt = _fe.context.create_entity_statement(
            'https://op.ntnu.no', 'https://foodle.uninett.no',
            metadata_policy={_fe.context.entity_type: metadata_policy},
            trust_anchor_id=statements[0].anchor,
            authority_hints=['https://feide.no'])

        claims = self.registration_service.parse_response(_jwt, request=_info['body'])

        assert set(claims.keys()) == {
            'application_type', 'client_secret',
            'client_id',
            "contacts",
            'federation_type',
            'grant_types',
            'id_token_signed_response_alg',
            'redirect_uris',
            'response_types',
            'token_endpoint_auth_method'
        }


class TestRpServiceAuto(object):
    @pytest.fixture(autouse=True)
    def rp_service_setup(self):
        entity_id = 'https://foodle.uninett.no'
        config = {
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            "key_conf": {"uri_path": "static/jwks.json", "key_defs": KEY_DEFS},
            "metadata": {
                "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                "id_token_signed_response_alg": "ES256",
                "token_endpoint_auth_method": "client_secret_basic",
                "token_endpoint_auth_signing_alg": "ES256",
                "federation_type": ['automatic']
            },
            "services": {
                'authorization': {
                    'class': 'idpyoidc.client.oidc.authorization.Authorization'
                },
                'access_token': {
                    'class': 'idpyoidc.client.oidc.access_token.AccessToken'
                }
            }, "federation": {
                "entity_id": entity_id,
                "key_conf": {"uri_path": "static/fed_jwks.json", "key_defs": KEY_DEFS},
                "endpoint": {
                    "fetch": {
                        "path": "fetch",
                        "class": Fetch,
                        "kwargs": {"client_authn_method": None},
                    }
                },
                "trusted_roots": ANCHOR,
                "authority_hints": ['https://ntnu.no'],
                "entity_type": 'openid_relying_party',
                "opponent_entity_type": 'openid_provider',
            }
        }

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
        self.entity = FederationRP(services=oidc_service, config=config, client_type='oidc')

        _context = self.entity.superior_get("service_context")
        _context.provider_info = {'token_endpoint': "https://op.example.org"}
        # httpc = Publisher(os.path.join(BASE_PATH, 'base_data'))

        # # The test data collector
        # _context.federation_entity.collector = DummyCollector(
        #     trusted_roots=ANCHOR, httpd=httpc, root_dir=os.path.join(BASE_PATH, 'base_data'))

    def test_construct_client_assertion(self):
        token_service = self.entity.superior_get("service", 'accesstoken')
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
