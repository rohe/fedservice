import json
import os

import pytest
from cryptojwt import KeyJar
from cryptojwt.key_jar import build_keyjar
from cryptojwt.key_jar import init_key_jar
from fedservice.entity_statement.statement import Statement
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase
from oidcservice.state_interface import State

from fedservice import FederationEntity
from fedservice.metadata_api.fs import read_info
from fedservice.op.registration import Registration
from fedservice.rp.provider_info_discovery import FedProviderInfoDiscovery
from fedservice.rp.registration import FedRegistration

from .utils import Publisher
from .utils import DummyCollector

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ENTITY_ID = 'https://foodle.uninett.no'

ANCHOR = {'https://feide.no': read_info(os.path.join(ROOT_DIR, 'feide.no'), "feide.no", "jwks")}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        service_context = ServiceContext(issuer=ENTITY_ID)
        op_entity_id = "https://op.ntnu.no"

        key_jar = KeyJar()
        key_jar.import_jwks(read_info(os.path.join(ROOT_DIR, 'foodle.uninett.no'),
                                      'foodle.uninett.no', 'jwks'),
                            issuer=ENTITY_ID)
        key_jar.import_jwks(read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
                            issuer=op_entity_id)

        self.rp_federation_entity = FederationEntity(
            key_jar=key_jar, entity_id=ENTITY_ID, trusted_roots=ANCHOR,
            authority_hints={'https://ntnu.no': ['https://feide.no']},
            entity_type='openid_client', opponent_entity_type='openid_provider'
        )

        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, root_dir=ROOT_DIR)

        service_context.federation_entity = self.rp_federation_entity
        db = InMemoryStateDataBase()
        db.set('state', State(iss='Issuer').to_json())
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context,
                                                  state_db=db),
            'registration': FedRegistration(service_context,
                                            state_db=db)
        }

        conf = {
            "issuer": op_entity_id,
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {},
            "jwks": {
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
            'template_dir': 'template'
        }
        endpoint_context = EndpointContext(conf, keyjar=build_keyjar(KEYSPEC))
        self.endpoint = Registration(endpoint_context)

        # === Federation stuff =======
        key_jar = KeyJar()
        key_jar.import_jwks(read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
                            issuer=op_entity_id)

        federation_entity = FederationEntity(
            op_entity_id, key_jar=key_jar, trusted_roots=ANCHOR,
            authority_hints={'https://ntnu.no': ['https://feide.no']},
            entity_type='openid_client',
            httpd=Publisher(ROOT_DIR),
            opponent_entity_type='openid_client')

        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.endpoint.endpoint_context.federation_entity = federation_entity

    def test_request(self):
        # construct the client registration request
        req_args = {
            'entity_id': self.rp_federation_entity.entity_id,
            'redirect_uris': ['https://foodle.uninett.no/cb']
        }
        self.rp_federation_entity.proposed_authority_hints = {
            'https://ntnu.no': ['https://feide.no']
        }
        self.service['registration'].service_context.provider_info[
            'registration'] = "https://op.ntnu.no/fedreg"
        jws = self.service['registration'].construct(request_args=req_args)
        assert jws

        res = self.endpoint.process_request(jws)
        assert res
        reg_resp = self.endpoint.do_response(res)
        assert set(reg_resp.keys()) == {'response', 'http_headers'}

        # This is cheating
        _fe = self.service['registration'].service_context.federation_entity
        statement = Statement()
        statement.metadata = self.endpoint.endpoint_context.provider_info
        statement.fo = "https://feide.no"
        _fe.op_statements = [statement]

        # parse response
        args = self.service['registration'].parse_response(reg_resp['response'])
        assert set(args.keys()) == {'response_args', 'cookie'}
