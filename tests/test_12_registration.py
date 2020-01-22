import os

import pytest
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from oidcendpoint.oidc import authorization

from fedservice.op import registration

from fedservice.op import provider_config
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase
from oidcservice.state_interface import State

from fedservice import FederationEntity
from fedservice.entity_statement.statement import Statement
from fedservice.metadata_api.fs2 import read_info
from fedservice.op.registration import Registration
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

ENTITY_ID = 'https://foodle.uninett.no'

ANCHOR = {'https://feide.no': read_info(os.path.join(ROOT_DIR, 'feide.no'), "feide.no", "jwks")}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        # First the RP
        service_context = ServiceContext(issuer=ENTITY_ID)

        # the federation part of the RP
        fed_key_jar = KeyJar()
        fed_key_jar.import_jwks(read_info(os.path.join(ROOT_DIR, 'foodle.uninett.no'),
                                      'foodle.uninett.no', 'jwks'),
                            issuer=ENTITY_ID)
        # key_jar.import_jwks(read_info(os.path.join(ROOT_DIR, 'ntnu.no'), 'ntnu.no', 'jwks'),
        #                     issuer=ENTITY_ID)

        self.rp_federation_entity = FederationEntity(
            key_jar=fed_key_jar, entity_id=ENTITY_ID, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party', opponent_entity_type='openid_provider'
        )

        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, root_dir=ROOT_DIR)

        # add the federation part to the service context
        service_context.federation_entity = self.rp_federation_entity
        db = InMemoryStateDataBase()
        db.set('state', State(iss='Issuer').to_json())

        # The RP has/supports 2 services
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context,
                                                  state_db=db),
            'registration': FedRegistration(service_context,
                                            state_db=db)
        }

        # and now for the OP
        op_entity_id = "https://op.ntnu.no"
        conf = {
            "issuer": op_entity_id,
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {
                'provider_info': {
                    'path': '.well-known/openid-federation',
                    'class': provider_config.ProviderConfiguration,
                    'kwargs': {'client_authn_method': None}
                },
                'federation_registration': {
                    'path': 'fed_registration',
                    'class': registration.Registration,
                    'kwargs': {'client_authn_method': None}
                },
                'authorization': {
                    'path': 'authorization',
                    'class': authorization.Authorization,
                    'kwargs': {
                        "response_modes_supported": ['query', 'fragment', 'form_post'],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                    }
                }
            },
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
        self.registration_endpoint = endpoint_context.endpoint["registration"]

        # === Federation stuff =======
        key_jar = KeyJar()
        key_jar.import_jwks(read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
                            issuer=op_entity_id)

        federation_entity = FederationEntity(
            op_entity_id, key_jar=key_jar, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party',
            httpd=Publisher(ROOT_DIR),
            opponent_entity_type='openid_relying_party')

        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.registration_endpoint.endpoint_context.federation_entity = federation_entity

    def test_registration(self):
        # This is cheating. Getting the OP provider info
        _fe = self.service['registration'].service_context.federation_entity
        statement = Statement()
        statement.metadata = self.registration_endpoint.endpoint_context.provider_info
        statement.fo = "https://feide.no"
        _fe.op_statements = [statement]
        # and the OP's federation keys
        self.rp_federation_entity.key_jar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer=self.registration_endpoint.endpoint_context.provider_info['issuer'])

        # construct the client registration request
        req_args = {
            'entity_id': self.rp_federation_entity.entity_id,
            'redirect_uris': ['https://foodle.uninett.no/cb']
        }
        self.rp_federation_entity.proposed_authority_hints = ['https://ntnu.no']

        self.service['registration'].service_context.provider_info[
            'registration'] = "https://op.ntnu.no/fedreg"
        jws = self.service['registration'].construct(request_args=req_args)
        assert jws

        # THe OP handles the registration request
        res = self.registration_endpoint.process_request(jws)
        assert res
        reg_resp = self.registration_endpoint.do_response(**res)
        assert set(reg_resp.keys()) == {'response', 'http_headers', 'cookie'}

        # The RP parses the OP's response
        args = self.service['registration'].parse_response(reg_resp['response'], request_body=jws)
        assert set(args.keys()) == {'entity_id', 'client_id', 'contacts', 'application_type',
                                    'redirect_uris', 'response_types', 'client_id_issued_at',
                                    'client_secret', 'grant_types', 'client_secret_expires_at'}
