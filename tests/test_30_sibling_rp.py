import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
import responses
from fedservice.entity_statement.collect import unverified_entity_statement

from fedservice.rp import RPHandler
from oidcrp.configure import Configuration

from fedservice import create_federation_entity
from fedservice.metadata_api.fs2 import FSEntityStatementAPI
from tests.utils import get_netloc

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ENTITY_ID = 'https://op.ntnu.no'


def init_rp_handler(config):
    rp_keys_conf = config.rp_keys
    _fed_conf = config.federation
    _fed_conf['keys'] = rp_keys_conf
    _httpc_params = config.httpc_params

    _fed_conf['entity_id'] = _fed_conf['entity_id'].format(domain=config.domain, port=config.port)
    federation_entity = create_federation_entity(httpc_params=_httpc_params, **_fed_conf)
    federation_entity.keyjar.httpc_params = _httpc_params

    _path = rp_keys_conf['uri_path']
    if _path.startswith('./'):
        _path = _path[2:]
    elif _path.startswith('/'):
        _path = _path[1:]

    return RPHandler(base_url=config.base_url, hash_seed=config.hash_seed,
                     jwks_path=_path, client_configs=config.clients,
                     services=config.services, httpc_params=_httpc_params,
                     federation_entity=federation_entity)


class TestEndpointPersistence(object):
    @pytest.fixture(autouse=True)
    def create_rph(self):
        _file = os.path.join(BASE_PATH, "conf_rp_auto.yaml")
        config = Configuration.create_from_config_file(_file)
        # Have to make it absolute, not relative
        config.federation['trusted_roots'] = os.path.join(BASE_PATH,
                                                          config.federation['trusted_roots'])
        config.federation['authority_hints'] = os.path.join(BASE_PATH,
                                                            config.federation['authority_hints'])

        self.rph = init_rp_handler(config)

        self.subject = 'https://op.ntnu.no'
        self.intermediate = 'https://ntnu.no'
        self.fedop = 'https://feide.no'

    def create_statements(self):
        res = {}
        # self-signed from subject
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.subject))
        res['subj_sesi'] = es_api.create_entity_statement(get_netloc(self.subject))
        # self-signed from intermediate
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.intermediate))
        res['inter_sesi'] = es_api.create_entity_statement(get_netloc(self.intermediate))
        # self-signed from fedop
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.fedop))
        res['fedop_sesi'] = es_api.create_entity_statement(get_netloc(self.fedop))

        # intermediate on subject
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.intermediate))
        res['inter_on_sub'] = es_api.create_entity_statement(get_netloc(self.subject))
        # fedop on intermediate
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.fedop))
        res['fedop_on_inter'] = es_api.create_entity_statement(get_netloc(self.intermediate))
        return res

    def test_discovery(self):
        stmts = self.create_statements()

        with responses.RequestsMock() as rsps:
            _url = "https://op.ntnu.no/.well-known/openid-federation?iss=https%3A%2F%2Fop.ntnu.no"
            rsps.add("GET", _url, body=stmts['subj_sesi'], status=200)

            _url = "https://ntnu.no/.well-known/openid-federation"
            rsps.add("GET", _url, body=stmts['inter_sesi'], status=200)

            _url = "https://feide.no/.well-known/openid-federation"
            rsps.add("GET", _url, body=stmts['fedop_sesi'], status=200)

            _url = 'https://ntnu.no/api?iss=https://ntnu.no&sub=https%3A%2F%2Fop.ntnu.no'
            rsps.add("GET", _url, body=stmts['inter_on_sub'], status=200)

            _url = 'https://feide.no/api?iss=https%3A%2F%2Ffeide.no&sub=https%3A%2F%2Fntnu.no'
            rsps.add("GET", _url, body=stmts['fedop_on_inter'], status=200)

            auth_req = self.rph.begin('ntnu')

        iss = self.rph.hash2issuer['ntnu']
        rp = self.rph.issuer2rp[iss]
        assert set(auth_req.keys()) == {'state', 'url'}
        p = urlparse(auth_req['url'])
        info = parse_qs(p.query)
        payload = unverified_entity_statement(info["request"][0])
        assert payload['client_id'] == rp.service_context.federation_entity.entity_id
        assert iss in payload['aud']
