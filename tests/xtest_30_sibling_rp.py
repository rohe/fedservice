import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

from idpyoidc.configure import create_from_config_file
from idpyoidc.client.configure import Configuration
import pytest
import responses

from fedservice.configure import DEFAULT_FED_FILE_ATTRIBUTE_NAMES
from fedservice.configure import FedEntityConfiguration
from fedservice.entity_statement.collect import unverified_entity_statement
from fedservice.fetch_entity_statement.fs2 import FSFetchEntityStatement
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
    rp_keys_conf = config.key_conf
    _fed_conf = config.federation
    if not _fed_conf.key_conf:
        _fed_conf.key_conf = rp_keys_conf
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
        _file = os.path.join(BASE_PATH, "conf_rp_auto.json")
        # automatic means no implicit registration
        config = create_from_config_file(Configuration,
                                         entity_conf=[
                                             {"class": FedEntityConfiguration,
                                              "attr": "federation",
                                              "path": ["federation"]}],
                                         filename=_file,
                                         base_path=BASE_PATH,
                                         file_attributes=DEFAULT_FED_FILE_ATTRIBUTE_NAMES)

        self.rph1 = init_rp_handler(config)
        self.rph2 = init_rp_handler(config)

        self.subject = 'https://op.umu.se'
        self.intermediate = 'https://umu.se'
        self.fedop = 'https://swamid.se'

    def create_statements(self):
        res = {}
        # self-signed from subject
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(self.subject))
        res['subj_sesi'] = es_api.create_entity_statement(get_netloc(self.subject))

        # self-signed from intermediate
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(self.intermediate))
        res['inter_sesi'] = es_api.create_entity_statement(get_netloc(self.intermediate))

        # self-signed from fedop
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(self.fedop))
        res['fedop_sesi'] = es_api.create_entity_statement(get_netloc(self.fedop))

        # intermediate on subject
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(self.intermediate))
        res['inter_on_sub'] = es_api.create_entity_statement(get_netloc(self.subject))

        # fedop1 on intermediate
        es_api = FSFetchEntityStatement(ROOT_DIR, iss=get_netloc(self.fedop))
        res['fedop_on_inter'] = es_api.create_entity_statement(get_netloc(self.intermediate))

        return res

    def test_discovery(self):
        stmts = self.create_statements()
        iss = 'https://op.umu.se'
        with responses.RequestsMock() as rsps:
            _url = "https://op.umu.se/.well-known/openid-federation?iss=https%3A%2F%2Fop.umu.se"
            rsps.add("GET", _url, body=stmts['subj_sesi'], status=200)

            _url = "https://umu.se/.well-known/openid-federation"
            rsps.add("GET", _url, body=stmts['inter_sesi'], status=200)

            _url = "https://swamid.se/.well-known/openid-federation"
            rsps.add("GET", _url, body=stmts['fedop_sesi'], status=200)

            _url = 'https://umu.se/fetch?iss=https://umu.se&sub=https%3A%2F%2Fop.umu.se'
            rsps.add("GET", _url, body=stmts['inter_on_sub'], status=200)

            _url = "https://swamid.se/fetch?iss=https%3A%2F%2Fswamid.se&sub=https%3A%2F%2Fumu.se"
            rsps.add("GET", _url, body=stmts['fedop_on_inter'], status=200)

            auth_req = self.rph1.begin('https://op.umu.se')

        rp = self.rph1.issuer2rp[iss]
        assert set(auth_req.keys()) == {'state', 'url'}
        p = urlparse(auth_req['url'])
        info = parse_qs(p.query)
        payload = unverified_entity_statement(info["request"][0])
        assert payload['client_id'] == rp.client_get("service_context").federation_entity.context.entity_id
        # assert iss in payload['aud']

        _federation_dump = rp.client_get("service_context").federation_entity.dump()

        rp2 = self.rph2.init_client(iss)
        rp2.client_get("service_context").federation_entity.load(_federation_dump)

        c = rp2.client_get("service_context").federation_entity.collector

        assert set(c.config_cache.keys()) == {'https://umu.se', 'https://swamid.se'}
        assert set(c.entity_statement_cache.keys()) == {
            'https://umu.se!!https://op.umu.se',
            'https://umu.se!exp!https://op.umu.se',
            'https://swamid.se!!https://umu.se',
            'https://swamid.se!exp!https://umu.se'}
