import os
import shutil

import pytest
import responses
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn

from fedservice.entity_statement.collect import unverified_entity_statement
from fedservice.metadata_api.fs2 import FSEntityStatementAPI
from fedservice.op import FederationEndpointContext
from fedservice.op.provider_config import ProviderConfiguration
from tests.utils import get_netloc

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

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
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {},
            "keys": {
                'key_defs': KEYSPEC,
                "private_path": "own/jwks.json",
                "uri_path": "static/jwks.json"
            },
            "authentication": {
                "anon": {
                    'acr': UNSPECIFIED,
                    "class": NoAuthn,
                    "kwargs": {"user": "diana"}
                }
            },
            'template_dir': 'template',
            'db_conf': {
                'keyjar': {
                    'handler': 'oidcmsg.storage.abfile.LabeledAbstractFileSystem',
                    'fdir': 'storage/keyjar',
                    'key_conv': 'oidcmsg.storage.converter.QPKey',
                    'value_conv': 'cryptojwt.serialize.item.KeyIssuer',
                    'label': 'x'
                },
                'default': {
                    'handler': 'oidcmsg.storage.abfile.AbstractFileSystem',
                    'fdir': 'storage',
                    'key_conv': 'oidcmsg.storage.converter.QPKey',
                    'value_conv': 'oidcmsg.storage.converter.JSON'
                },
                'session': {
                    'handler': 'oidcmsg.storage.abfile.AbstractFileSystem',
                    'fdir': 'storage/session',
                    'key_conv': 'oidcmsg.storage.converter.QPKey',
                    'value_conv': 'oidcmsg.storage.converter.JSON'
                },
                'sso': {
                    'handler': 'oidcmsg.storage.abfile.AbstractFileSystem',
                    'fdir': 'storage/sso',
                    'key_conv': 'oidcmsg.storage.converter.QPKey',
                    'value_conv': 'oidcmsg.storage.converter.JSON'
                }
            },
            'federation': {
                'entity_id': ENTITY_ID,
                'signing_keys': {
                    'private_path': 'private/fed_keys.json',
                    'key_defs': KEYSPEC,
                    'public_path': 'static/fed_keys.json',
                    'read_only': False
                },
                'priority': [],
                'entity_type': 'openid_provider',
                'opponent_entity_type': 'openid_relying_party',
                'registration_type': 'explicit',
                'db_conf': {
                    'abstract_storage_cls': 'oidcmsg.storage.extension.LabeledAbstractStorage',
                    "default": {
                        'handler': 'oidcmsg.storage.abfile.AbstractFileSystem',
                        'fdir': 'storage/fed',
                        'key_conv': 'oidcmsg.storage.converter.QPKey',
                        'value_conv': 'oidcmsg.storage.converter.JSON'
                    },
                    "config": {
                        'handler': 'oidcmsg.storage.abfile.AbstractFileSystem',
                        'fdir': 'storage/fed/config',
                        'key_conv': 'oidcmsg.storage.converter.QPKey',
                        'value_conv': 'oidcmsg.storage.converter.JSON'
                    },
                    "entity_statement": {
                        'handler': 'oidcmsg.storage.abfile.AbstractFileSystem',
                        'fdir': 'storage/fed/entity_statement',
                        'key_conv': 'oidcmsg.storage.converter.QPKey',
                        'value_conv': 'oidcmsg.storage.converter.JSON'
                    },
                    "keyjar": {
                        'handler': 'oidcmsg.storage.abfile.AbstractFileSystem',
                        'fdir': 'storage/fed/keyjar',
                        'key_conv': 'oidcmsg.storage.converter.QPKey',
                        'value_conv': 'cryptojwt.serialize.item.KeyIssuer',
                        'label': 'x'
                    }
                }
            }
        }
        conf['federation']['trusted_roots'] = os.path.join(BASE_PATH, 'trusted_roots.json')
        conf['federation']['authority_hints'] = os.path.join(BASE_PATH, 'authority_hints.json')

        endpoint_context = FederationEndpointContext(conf)
        self.endpoint = ProviderConfiguration(endpoint_context)

    def test_collect_intermediate(self):
        _collector = self.endpoint.endpoint_context.federation_entity.collector
        subject = 'https://op.ntnu.no'
        intermediate = 'https://ntnu.no'
        fedop = 'https://feide.no'
        # self-signed from subject
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(subject))
        subj_sesi = es_api.create_entity_statement(get_netloc(subject))
        # self-signed from intermediate
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(intermediate))
        inter_sesi = es_api.create_entity_statement(get_netloc(intermediate))
        # self-signed from fedop
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(fedop))
        fedop_sesi = es_api.create_entity_statement(get_netloc(fedop))

        # intermediate on subject
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(intermediate))
        inter_on_sub = es_api.create_entity_statement(get_netloc(subject))
        # fedop on intermediate
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(fedop))
        fedop_on_inter = es_api.create_entity_statement(get_netloc(intermediate))

        with responses.RequestsMock() as rsps:
            _url = "{}/.well-known/openid-federation".format(intermediate)
            rsps.add("GET", _url, body=inter_sesi, status=200)

            _url = "{}/.well-known/openid-federation".format(fedop)
            rsps.add("GET", _url, body=fedop_sesi, status=200)

            _url = 'https://ntnu.no/api?iss=https%3A%2F%2Fntnu.no&sub=https%3A%2F%2Fop.ntnu.no'
            rsps.add("GET", _url, body=inter_on_sub, status=200)

            _url = 'https://feide.no/api?iss=https%3A%2F%2Ffeide.no&sub=https%3A%2F%2Fntnu.no'
            rsps.add("GET", _url, body=fedop_on_inter, status=200)

            tree = _collector.collect_intermediate(subject, 'https://ntnu.no')
            assert tree

        assert len(_collector.config_cache) == 2
        assert set(_collector.config_cache.keys()) == {'https://ntnu.no', 'https://feide.no'}

        # The unpacked fedop's self signed entity statement
        _info = _collector.config_cache['https://feide.no']
        assert _info['sub'] == fedop
        assert _info['iss'] == fedop
        assert _info['metadata']['federation_entity']['federation_api_endpoint'] == \
               'https://feide.no/api'

        # For each entity statement there is also the expiration time
        assert len(_collector.entity_statement_cache) == 4
        assert set(_collector.entity_statement_cache.keys()) == {
            'https://feide.no!!https://ntnu.no',
            'https://feide.no!exp!https://ntnu.no',
            'https://ntnu.no!!https://op.ntnu.no',
            'https://ntnu.no!exp!https://op.ntnu.no'}

        # have a look at the payload
        _info = unverified_entity_statement(
            _collector.entity_statement_cache['https://feide.no!!https://ntnu.no'])
        assert _info['sub'] == intermediate
        assert _info['iss'] == fedop
        assert _info['authority_hints'] == [fedop]
