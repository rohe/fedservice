import os
import shutil
from urllib.parse import parse_qs
from urllib.parse import urlparse

from oidcrp.configure import Configuration
import pytest
import responses

from fedservice.entity_statement.collect import unverified_entity_statement
from fedservice.metadata_api.fs2 import FSEntityStatementAPI
from fedservice.rp import RPHandler
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

    _path = rp_keys_conf['uri_path']
    if _path.startswith('./'):
        _path = _path[2:]
    elif _path.startswith('/'):
        _path = _path[1:]

    return RPHandler(base_url=config.base_url, hash_seed=config.hash_seed,
                     jwks_path=_path, client_configs=config.clients,
                     services=config.services, httpc_params=_httpc_params,
                     federation_entity_config=_fed_conf)


class TestEndpointPersistence(object):
    @pytest.fixture(autouse=True)
    def create_rph(self):
        try:
            shutil.rmtree('storage')
        except FileNotFoundError:
            pass

        _file = os.path.join(BASE_PATH, "conf_rp_auto.yaml")
        config = Configuration.create_from_config_file(_file)
        # Have to make it absolute, not relative
        config.federation['trusted_roots'] = os.path.join(BASE_PATH,
                                                          config.federation['trusted_roots'])
        config.federation['authority_hints'] = os.path.join(BASE_PATH,
                                                            config.federation['authority_hints'])
        config.federation['entity_id'] = config.federation['entity_id'].format(
            domain=config.domain, port=config.port)

        self.rph1 = init_rp_handler(config)
        self.rph2 = init_rp_handler(config)

        self.subject = 'https://op.ntnu.no'
        self.intermediate = 'https://ntnu.no'
        self.fedop1 = 'https://feide.no'
        self.fedop2 = 'https://swamid.se'

    def create_statements(self):
        res = {}
        # self-signed from subject
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.subject))
        res['subj_sesi'] = es_api.create_entity_statement(get_netloc(self.subject))
        # self-signed from intermediate
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.intermediate))
        res['inter_sesi'] = es_api.create_entity_statement(get_netloc(self.intermediate))

        # self-signed from fedop1
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.fedop1))
        res['fedop1_sesi'] = es_api.create_entity_statement(get_netloc(self.fedop1))

        # self-signed from fedop2
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.fedop2))
        res['fedop2_sesi'] = es_api.create_entity_statement(get_netloc(self.fedop2))

        # intermediate on subject
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.intermediate))
        res['inter_on_sub'] = es_api.create_entity_statement(get_netloc(self.subject))

        # fedop1 on intermediate
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.fedop1))
        res['fedop1_on_inter'] = es_api.create_entity_statement(get_netloc(self.intermediate))

        # fedop2 on intermediate
        es_api = FSEntityStatementAPI(ROOT_DIR, iss=get_netloc(self.fedop2))
        res['fedop2_on_inter'] = es_api.create_entity_statement(get_netloc(self.intermediate))
        return res

    def test_discovery(self):
        stmts = self.create_statements()

        with responses.RequestsMock() as rsps:
            _url = "https://op.ntnu.no/.well-known/openid-federation?iss=https%3A%2F%2Fop.ntnu.no"
            rsps.add("GET", _url, body=stmts['subj_sesi'], status=200)

            _url = "https://ntnu.no/.well-known/openid-federation"
            rsps.add("GET", _url, body=stmts['inter_sesi'], status=200)

            _url = "https://feide.no/.well-known/openid-federation"
            rsps.add("GET", _url, body=stmts['fedop1_sesi'], status=200)

            _url = "https://swamid.se/.well-known/openid-federation"
            rsps.add("GET", _url, body=stmts['fedop2_sesi'], status=200)

            _url = 'https://ntnu.no/api?iss=https://ntnu.no&sub=https%3A%2F%2Fop.ntnu.no'
            rsps.add("GET", _url, body=stmts['inter_on_sub'], status=200)

            _url = 'https://feide.no/api?iss=https%3A%2F%2Ffeide.no&sub=https%3A%2F%2Fntnu.no'
            rsps.add("GET", _url, body=stmts['fedop1_on_inter'], status=200)

            _url = "https://swamid.se/api?iss=https%3A%2F%2Fswamid.se&sub=https%3A%2F%2Fntnu.no"
            rsps.add("GET", _url, body=stmts['fedop2_on_inter'], status=200)

            auth_req = self.rph1.begin('ntnu')

        iss = self.rph1.hash2issuer['ntnu']
        rp = self.rph1.issuer2rp[iss]
        assert set(auth_req.keys()) == {'state', 'url'}
        p = urlparse(auth_req['url'])
        info = parse_qs(p.query)
        payload = unverified_entity_statement(info["request"][0])
        assert payload['client_id'] == rp.client_get("service_context").federation_entity.entity_id
        # assert iss in payload['aud']

        _federation_dump = rp.client_get("service_context").federation_entity.dump()

        rp2 = self.rph2.init_client(iss)
        rp2.client_get("service_context").federation_entity.load(_federation_dump)
        c = rp2.client_get("service_context").federation_entity.collector

        assert set(c.config_cache.keys()) == {'https://ntnu.no', 'https://feide.no',
                                              'https://swamid.se'}
        assert set(c.entity_statement_cache.keys()) == {
            'https://feide.no!!https://ntnu.no',
            'https://feide.no!exp!https://ntnu.no',
            'https://ntnu.no!!https://op.ntnu.no',
            'https://ntnu.no!exp!https://op.ntnu.no',
            'https://swamid.se!!https://ntnu.no',
            'https://swamid.se!exp!https://ntnu.no'}
