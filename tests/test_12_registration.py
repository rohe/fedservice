import os

import pytest
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.key_jar import build_keyjar
from oidcendpoint import JWT_BEARER
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn
from oidcmsg.oidc import AuthorizationRequest
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase
from oidcservice.state_interface import State

from fedservice import FederationEntity
from fedservice.entity_statement.statement import Statement
from fedservice.metadata_api.fs2 import read_info
from fedservice.op import authorization
from fedservice.op import provider_config
from fedservice.op import registration
from fedservice.rp.authorization import FedAuthorization
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
        service_context = ServiceContext(issuer=ENTITY_ID, keyjar=build_keyjar(KEYSPEC))

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
                                            state_db=db),
            'authorization': FedAuthorization(service_context,
                                              state_db=db),
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
                        "client_authn_method": ['private_key_jwt']
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
            'template_dir': 'template',
            'add_on': {
                "automatic_registration": {
                    "function":
                        "fedservice.op.add_on.automatic_registration.add_automatic_registration_support",
                    "kwargs": {"new_id": True}  # default False
                }
            }
        }
        endpoint_context = EndpointContext(conf, keyjar=build_keyjar(KEYSPEC))
        self.registration_endpoint = endpoint_context.endpoint["registration"]
        self.authorization_endpoint = endpoint_context.endpoint["authorization"]

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

    def test_explicit_registration(self):
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

    def test_automatic_registration_new_client_id(self):
        # This is cheating. Getting the OP's provider info
        _fe = self.service['registration'].service_context.federation_entity
        statement = Statement()
        statement.metadata = self.registration_endpoint.endpoint_context.provider_info
        statement.fo = "https://feide.no"
        _fe.op_statements = [statement]
        # and the OP's federation keys
        self.rp_federation_entity.key_jar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer=self.registration_endpoint.endpoint_context.provider_info['issuer'])

        # Create the private_kwy_jwt parts

        _jwt = JWT(self.service['registration'].service_context.keyjar,
                   iss=ENTITY_ID,
                   sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack(
            {"aud": [self.authorization_endpoint.endpoint_context.provider_info[
                         "authorization_endpoint"]]})

        authn_request = AuthorizationRequest(
            response_type="code", state="af0ifjsldkj",
            client_id=ENTITY_ID, redirect_uri="{}/callback".format(ENTITY_ID),
            code_challenge="K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
            code_challenge_method="S256", scope=["ais", "openid"]
        )

        authn_request.update({"client_assertion": _assertion, "client_assertion_type": JWT_BEARER})

        # Have to provide the OP with clients keys
        self.authorization_endpoint.endpoint_context.keyjar.import_jwks(
            self.service['registration'].service_context.keyjar.export_jwks(),
            ENTITY_ID
        )

        # The OP handles the authorization request
        req = self.authorization_endpoint.parse_request(authn_request.to_dict())
        assert "response_type" in req

        client_ids = list(self.authorization_endpoint.endpoint_context.cdb.keys())
        assert len(client_ids) == 1
        assert client_ids[0] != ENTITY_ID
        # reg_resp = self.registration_endpoint.do_response(**res)
        # assert set(reg_resp.keys()) == {'response', 'http_headers', 'cookie'}

    def test_automatic_registration_keep_client_id(self):
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

        # Create the private_kwy_jwt parts

        _jwt = JWT(self.service['registration'].service_context.keyjar,
                   iss=ENTITY_ID,
                   sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack(
            {"aud": [self.authorization_endpoint.endpoint_context.provider_info[
                         "authorization_endpoint"]]})

        authn_request = AuthorizationRequest(
            response_type="code", state="af0ifjsldkj",
            client_id=ENTITY_ID, redirect_uri="{}/callback".format(ENTITY_ID),
            code_challenge="K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
            code_challenge_method="S256", scope=["ais", "openid"]
        )

        authn_request.update({"client_assertion": _assertion, "client_assertion_type": JWT_BEARER})

        # Have to provide the OP with clients keys
        self.authorization_endpoint.endpoint_context.keyjar.import_jwks(
            self.service['registration'].service_context.keyjar.export_jwks(),
            ENTITY_ID
        )

        # set new_id to False
        self.authorization_endpoint.automatic_registration_endpoint.kwargs["new_id"] = False

        # THe OP handles the authorization request
        req = self.authorization_endpoint.parse_request(authn_request.to_dict())
        assert "response_type" in req

        # reg_resp = self.registration_endpoint.do_response(**res)
        # assert set(reg_resp.keys()) == {'response', 'http_headers', 'cookie'}

        client_ids = list(self.authorization_endpoint.endpoint_context.cdb.keys())
        assert len(client_ids) == 1
        assert client_ids[0] == ENTITY_ID

