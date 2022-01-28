import os
import shutil
from time import sleep

from fedservice.entity.fetch import Fetch
from fedservice.entity_statement.collect import Collector
from oidcop.user_authn.authn_context import UNSPECIFIED
from oidcop.user_authn.user import NoAuthn
import pytest
import responses

from fedservice.entity_statement.collect import unverified_entity_statement
from fedservice.fetch_entity_statement.fs2 import FSFetchEntityStatement
from fedservice.op import FederationServer
from fedservice.op.provider_config import ProviderConfiguration
from fedservice.server import Server
from tests.utils import get_netloc

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

ROOT_DIR = os.path.join(BASE_PATH, 'base_data')


def full_path(path):
    return os.path.join(BASE_PATH, path)


KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ENTITY_ID = 'https://op.ntnu.no'


class TestEndpointPersistence(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        try:
            shutil.rmtree('storage')
        except FileNotFoundError:
            pass

        conf = {
            "issuer": ENTITY_ID,
            "password": "mycket hemligt",
            "claims_interface": {"class": "oidcop.session.claims.ClaimsInterface", "kwargs": {}},
            "verify_ssl": False,
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {"client_authn_method": None},
                },
            },
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"},
                        {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "token"},
                        {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "refresh"}
                    ],
                },
                "code": {"kwargs": {"lifetime": 600}},
                "token": {"kwargs": {"lifetime": 3600}},
                "refresh": {"kwargs": {"lifetime": 3600}},
            },
            "keys": {
                'key_defs': KEYSPEC,
                "private_path": full_path("own/jwks.json"),
                "uri_path": full_path("static/jwks.json")
            },
            "authentication": {
                "anon": {
                    'acr': UNSPECIFIED,
                    "class": NoAuthn,
                    "kwargs": {"user": "diana"}
                }
            },
            'template_dir': 'template',
            'federation': {
                'entity_id': ENTITY_ID,
                'signing_keys': {
                    'private_path': full_path('private/fed_keys.json'),
                    'key_defs': KEYSPEC,
                    'public_path': full_path('static/fed_keys.json'),
                    'read_only': False
                },
                "endpoint": {
                    "fetch": {
                        "path": "fetch",
                        "class": Fetch,
                        "kwargs": {"client_authn_method": None},
                    }
                },
                'priority': [],
                'entity_type': 'openid_provider',
                'opponent_entity_type': 'openid_relying_party',
                'registration_type': 'explicit'
            }
        }
        conf['federation']['trusted_roots'] = full_path('trusted_roots.json')
        conf['federation']['authority_hints'] = full_path('authority_hints.json')

        server = FederationServer(conf)
        self.endpoint = server.server_get("endpoint", "provider_config")

    def test_collect_intermediate(self):
        _collector = self.endpoint.server_get("endpoint_context").federation_entity.collector
        subject = 'https://op.ntnu.no'
        intermediate = 'https://ntnu.no'
        fedop1 = 'https://feide.no'
        fedop2 = 'https://swamid.se'
        # self-signed from subject
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(subject))
        subj_sesi = es_api.create_entity_statement(get_netloc(subject))
        # self-signed from intermediate
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(intermediate))
        inter_sesi = es_api.create_entity_statement(get_netloc(intermediate))
        # self-signed from fedop
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(fedop1))
        fedop_sesi_1 = es_api.create_entity_statement(get_netloc(fedop1))
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(fedop2))
        fedop_sesi_2 = es_api.create_entity_statement(get_netloc(fedop2))

        # intermediate on subject
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(intermediate))
        inter_on_sub = es_api.create_entity_statement(get_netloc(subject))
        # fedop on intermediate
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(fedop1))
        fedop_on_inter_1 = es_api.create_entity_statement(get_netloc(intermediate))
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(fedop2))
        fedop_on_inter_2 = es_api.create_entity_statement(get_netloc(intermediate))

        sleep(1)

        with responses.RequestsMock() as rsps:
            _url = "{}/.well-known/openid-federation".format(intermediate)
            rsps.add("GET", _url, body=inter_sesi, status=200)

            _url = "{}/.well-known/openid-federation".format(fedop1)
            rsps.add("GET", _url, body=fedop_sesi_1, status=200)

            _url = "{}/.well-known/openid-federation".format(fedop2)
            rsps.add("GET", _url, body=fedop_sesi_2, status=200)

            _url = 'https://ntnu.no/fetch?iss=https%3A%2F%2Fntnu.no&sub=https%3A%2F%2Fop.ntnu.no'
            rsps.add("GET", _url, body=inter_on_sub, status=200)

            _url = 'https://feide.no/fetch?iss=https%3A%2F%2Ffeide.no&sub=https%3A%2F%2Fntnu.no'
            rsps.add("GET", _url, body=fedop_on_inter_1, status=200)

            _url = 'https://swamid.se/fetch?iss=https%3A%2F%2Fswamid.se&sub=https%3A%2F%2Fntnu.no'
            rsps.add("GET", _url, body=fedop_on_inter_2, status=200)

            tree = _collector.collect_intermediate(subject, 'https://ntnu.no')
            assert tree

        assert len(_collector.config_cache) == 3
        assert set(_collector.config_cache.keys()) == {'https://ntnu.no', 'https://feide.no',
                                                       'https://swamid.se'}

        # The unpacked fedop1's self signed entity statement
        _info = _collector.config_cache['https://feide.no']
        assert _info['sub'] == fedop1
        assert _info['iss'] == fedop1
        assert _info['metadata']['federation_entity']['federation_fetch_endpoint'] == 'https://feide.no/fetch'

        # For each entity statement there is also the expiration time
        assert len(_collector.entity_statement_cache) == 6
        assert set(_collector.entity_statement_cache.keys()) == {
            'https://feide.no!!https://ntnu.no',
            'https://feide.no!exp!https://ntnu.no',
            'https://ntnu.no!!https://op.ntnu.no',
            'https://ntnu.no!exp!https://op.ntnu.no',
            'https://swamid.se!!https://ntnu.no',
            'https://swamid.se!exp!https://ntnu.no'
        }

        # have a look at the payload
        _info = unverified_entity_statement(
            _collector.entity_statement_cache['https://swamid.se!!https://ntnu.no'])
        assert _info['sub'] == intermediate
        assert _info['iss'] == fedop2
        assert _info['authority_hints'] == [fedop2]

        _collector_dump = _collector.dump()

        _c2 = Collector()
        _c2.load(_collector_dump)

        assert len(_c2.config_cache) == 3
        assert set(_c2.config_cache.keys()) == {'https://ntnu.no', 'https://feide.no', 'https://swamid.se'}

        # The unpacked fedop1's self signed entity statement
        _info = _c2.config_cache['https://feide.no']
        assert _info['sub'] == fedop1
        assert _info['iss'] == fedop1
        assert _info['metadata']['federation_entity']['federation_fetch_endpoint'] == 'https://feide.no/fetch'

        # For each entity statement there is also the expiration time
        assert len(_c2.entity_statement_cache) == 6
        assert set(_c2.entity_statement_cache.keys()) == {
            'https://feide.no!!https://ntnu.no',
            'https://feide.no!exp!https://ntnu.no',
            'https://ntnu.no!!https://op.ntnu.no',
            'https://ntnu.no!exp!https://op.ntnu.no',
            'https://swamid.se!!https://ntnu.no',
            'https://swamid.se!exp!https://ntnu.no'
        }

        # have a look at the payload
        _info = unverified_entity_statement(_c2.entity_statement_cache['https://swamid.se!!https://ntnu.no'])
        assert _info['sub'] == intermediate
        assert _info['iss'] == fedop2
        assert _info['authority_hints'] == [fedop2]
