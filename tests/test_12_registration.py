import os

from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn
from oidcservice.exception import OtherError
from oidcservice.service_context import ServiceContext
import pytest

from fedservice import FederationEntity
from fedservice.entity_statement.statement import TrustChain
from fedservice.metadata_api.fs2 import read_info
from fedservice.op import authorization
from fedservice.op import provider_config
from fedservice.op import registration
from fedservice.rp.authorization import FedAuthorization
from fedservice.rp.provider_info_discovery import FedProviderInfoDiscovery
from fedservice.rp.registration import Registration
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


class TestExplicit(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        # First the RP
        service_context = ServiceContext(config={
            'behaviour': {
                'federation_types_supported': ['explicit']
            },
            'issuer': "https://op.ntnu.no",
            'keys': {'key_defs': KEYSPEC}
        })

        # the federation part of the RP
        self.rp_federation_entity = FederationEntity(
            entity_id=ENTITY_ID, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party', opponent_entity_type='openid_provider'
        )

        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, root_dir=ROOT_DIR)

        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'foodle.uninett.no'), 'foodle.uninett.no', 'jwks'),
            issuer_id=ENTITY_ID)

        # add the federation part to the service context
        service_context.federation_entity = self.rp_federation_entity

        # The RP has/supports 3 services
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context),
            'registration': Registration(service_context),
            'authorization': FedAuthorization(service_context),
        }

        # and now for the OP
        op_entity_id = "https://op.ntnu.no"
        conf = {
            "issuer": op_entity_id,
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "httpc_param": {'verify': False},
            "endpoint": {
                'provider_info': {
                    'path': '.well-known/openid-federation',
                    'class': provider_config.ProviderConfiguration,
                    'kwargs': {'client_authn_method': None}
                },
                'registration': {
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
                        "client_authn_method": ['request_param']
                    }
                }
            },
            "keys": {
                "private_path": "own/jwks.json",
                "uri_path": "static/jwks.json",
                "key_defs": KEYSPEC
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
        endpoint_context = EndpointContext(conf)
        # endpoint_context.keyjar.httpc_params = endpoint_context.httpc_params

        self.registration_endpoint = endpoint_context.endpoint["registration"]
        self.authorization_endpoint = endpoint_context.endpoint["authorization"]
        self.provider_endpoint = endpoint_context.endpoint["provider_config"]

        # === Federation stuff =======
        federation_entity = FederationEntity(
            op_entity_id, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party',
            httpd=Publisher(ROOT_DIR),
            opponent_entity_type='openid_relying_party')

        federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=op_entity_id)

        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.registration_endpoint.endpoint_context.federation_entity = federation_entity

    def test_explicit_registration(self):
        _registration_service = self.service['registration']
        # Using the RP's federation entity instance
        _fe = _registration_service.service_context.federation_entity

        # This is cheating. Getting the OP provider info
        trust_chain = TrustChain()
        trust_chain.metadata = self.registration_endpoint.endpoint_context.provider_info
        trust_chain.anchor = "https://feide.no"
        trust_chain.verified_chain = [{'iss': "https://ntnu.no"}]

        self.service['discovery'].update_service_context([trust_chain])
        # add the OP's federation keys
        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.endpoint_context.provider_info['issuer'])

        # construct the client registration request
        req_args = {
            'entity_id': self.rp_federation_entity.entity_id,
            'redirect_uris': ['https://foodle.uninett.no/cb']
        }
        self.rp_federation_entity.proposed_authority_hints = ['https://ntnu.no']

        jws = _registration_service.construct(request_args=req_args)
        assert jws

        # THe OP handles the registration request
        res = self.registration_endpoint.process_request(jws)
        assert res
        reg_resp = self.registration_endpoint.do_response(**res)
        assert set(reg_resp.keys()) == {'response', 'http_headers', 'cookie'}

        # The RP parses the OP's response
        args = _registration_service.parse_response(reg_resp['response'], request=jws)
        assert set(args.keys()) == {'entity_id', 'client_id', 'contacts', 'application_type',
                                    'redirect_uris', 'response_types', 'client_id_issued_at',
                                    'client_secret', 'grant_types', 'client_secret_expires_at'}


class TestAutomatic(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        # First the RP
        service_context = ServiceContext(config={
            'behaviour': {
                'federation_types_supported': ['explicit']
            },
            'issuer': "https://op.ntnu.no",
            'keys': {'key_defs': KEYSPEC}
        })

        # the federation part of the RP
        self.rp_federation_entity = FederationEntity(
            entity_id=ENTITY_ID, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party', opponent_entity_type='openid_provider'
        )

        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, root_dir=ROOT_DIR)

        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'foodle.uninett.no'), 'foodle.uninett.no', 'jwks'),
            issuer_id=ENTITY_ID)

        # add the federation part to the service context
        service_context.federation_entity = self.rp_federation_entity

        # The RP has/supports 3 services
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context),
            'registration': Registration(service_context),
            'authorization': FedAuthorization(service_context,
                                              conf={"request_object_expires_in": 300}),
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
                'registration': {
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
                        "client_authn_method": ['request_param']
                    }
                }
            },
            "keys": {
                "private_path": "own/jwks.json",
                "uri_path": "static/jwks.json",
                "key_defs": KEYSPEC
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
                        "fedservice.op.add_on.automatic_registration.add_support",
                    "kwargs": {
                        "new_id": False,  # default False
                        'client_registration_authn_methods_supported': {"ar": ['request_object']},
                        'where': ['authorization']
                    }
                }
            }
        }
        endpoint_context = EndpointContext(conf)
        self.registration_endpoint = endpoint_context.endpoint["registration"]
        self.authorization_endpoint = endpoint_context.endpoint["authorization"]
        self.provider_endpoint = endpoint_context.endpoint["provider_config"]

        # === Federation stuff =======
        federation_entity = FederationEntity(
            op_entity_id, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party',
            httpd=Publisher(ROOT_DIR),
            opponent_entity_type='openid_relying_party')

        federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=op_entity_id)

        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.registration_endpoint.endpoint_context.federation_entity = federation_entity

    def test_automatic_registration_new_client_id(self):
        _registration_service = self.service['registration']

        self.authorization_endpoint.endpoint_context.provider_info[
            'client_registration_authn_methods_supported'] = {"ar": ['request_object']}
        self.authorization_endpoint.automatic_registration_endpoint.kwargs['new_id'] = True
        # This is cheating. Getting the OP's provider info
        _fe = _registration_service.service_context.federation_entity
        statement = TrustChain()
        statement.metadata = self.registration_endpoint.endpoint_context.provider_info
        statement.anchor = "https://feide.no"
        statement.verified_chain = [{'iss': "https://ntnu.no"}]

        self.service['discovery'].update_service_context([statement])
        # and the OP's federation keys
        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.endpoint_context.provider_info['issuer'])

        _context = self.service['authorization'].service_context
        _context.set('issuer', 'https://op.ntnu.no')
        _context.set('redirect_uris', ['https://foodle.uninett.no/callback'])
        _context.set('entity_id', self.rp_federation_entity.entity_id)
        _context.set('client_id', self.rp_federation_entity.entity_id)
        _context.set('behaviour', {'response_types': ['code']})
        _context.set('provider_info', self.authorization_endpoint.endpoint_context.provider_info)
        authn_request = self.service['authorization'].construct()

        # Have to provide the OP with clients keys
        self.authorization_endpoint.endpoint_context.keyjar.import_jwks(
            _registration_service.service_context.keyjar.export_jwks(),
            ENTITY_ID
        )

        # The OP handles the authorization request
        req = self.authorization_endpoint.parse_request(authn_request.to_dict())
        assert "response_type" in req

        client_ids = list(self.authorization_endpoint.endpoint_context.cdb.keys())
        assert len(client_ids) == 2  # dynamic and entity_id
        assert ENTITY_ID in client_ids

    def test_automatic_registration_keep_client_id(self):
        # This is cheating. Getting the OP provider info
        _registration_service = self.service['registration']
        _fe = _registration_service.service_context.federation_entity
        statement = TrustChain()
        statement.metadata = self.registration_endpoint.endpoint_context.provider_info
        statement.anchor = "https://feide.no"
        statement.verified_chain = [{'iss': "https://ntnu.no"}]

        self.service['discovery'].update_service_context([statement])

        # and the OP's federation keys
        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.endpoint_context.provider_info['issuer'])

        service_context = self.service['authorization'].service_context
        service_context.set('issuer', 'https://op.ntnu.no')
        service_context.set('redirect_uris', ['https://foodle.uninett.no/callback'])
        service_context.set('entity_id', self.rp_federation_entity.entity_id)
        service_context.set('client_id', self.rp_federation_entity.entity_id)
        service_context.set('behaviour', {'response_types': ['code']})
        service_context.set('provider_info',
                            self.authorization_endpoint.endpoint_context.provider_info)

        authn_request = self.service['authorization'].construct()
        # Have to provide the OP with clients keys
        self.authorization_endpoint.endpoint_context.keyjar.import_jwks(
            _registration_service.service_context.keyjar.export_jwks(),
            ENTITY_ID
        )

        # get rid of the earlier client registrations
        for k in self.authorization_endpoint.endpoint_context.cdb.keys():
            del self.authorization_endpoint.endpoint_context.cdb[k]

        # Have to provide the OP with clients keys
        self.authorization_endpoint.endpoint_context.keyjar.import_jwks(
            _registration_service.service_context.keyjar.export_jwks(),
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


class TestAutomaticNoSupport(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        # First the RP
        service_context = ServiceContext(config={
            'behaviour': {
                'federation_types_supported': ['explicit']
            },
            'issuer': "https://op.ntnu.no",
            'keys': {'key_defs': KEYSPEC}
        })

        # the federation part of the RP
        self.rp_federation_entity = FederationEntity(
            entity_id=ENTITY_ID, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party', opponent_entity_type='openid_provider'
        )

        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, root_dir=ROOT_DIR)

        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'foodle.uninett.no'), 'foodle.uninett.no', 'jwks'),
            issuer_id=ENTITY_ID)

        # add the federation part to the service context
        service_context.federation_entity = self.rp_federation_entity

        # The RP has/supports 3 services
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context),
            'registration': Registration(service_context),
            'authorization': FedAuthorization(service_context),
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
                'registration': {
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
                        "client_authn_method": ['request_param']
                    }
                }
            },
            "keys": {
                "private_path": "own/jwks.json",
                "uri_path": "static/jwks.json",
                "key_defs": KEYSPEC
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
        endpoint_context = EndpointContext(conf)
        self.registration_endpoint = endpoint_context.endpoint["registration"]
        self.authorization_endpoint = endpoint_context.endpoint["authorization"]
        self.provider_endpoint = endpoint_context.endpoint["provider_config"]

        # === Federation stuff =======
        federation_entity = FederationEntity(
            op_entity_id, trusted_roots=ANCHOR,
            authority_hints=['https://ntnu.no'],
            entity_type='openid_relying_party',
            httpd=Publisher(ROOT_DIR),
            opponent_entity_type='openid_relying_party')

        federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=op_entity_id)

        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

        self.registration_endpoint.endpoint_context.federation_entity = federation_entity

    def test_automatic_registration_new_client_id(self):
        _registration_service = self.service['registration']

        # This is cheating. Getting the OP's provider info
        _fe = _registration_service.service_context.federation_entity
        statement = TrustChain()
        statement.metadata = self.registration_endpoint.endpoint_context.provider_info
        statement.anchor = "https://feide.no"
        statement.verified_chain = [{'iss': "https://ntnu.no"}]

        self.service['discovery'].update_service_context([statement])
        # and the OP's federation keys
        self.rp_federation_entity.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.endpoint_context.provider_info['issuer'])

        _context = self.service['authorization'].service_context
        _context.set('issuer', 'https://op.ntnu.no')
        _context.set('redirect_uris', ['https://foodle.uninett.no/callback'])
        _context.set('entity_id', self.rp_federation_entity.entity_id)
        _context.set('client_id', self.rp_federation_entity.entity_id)
        _context.set('behaviour', {'response_types': ['code']})
        _context.set('provider_info', self.authorization_endpoint.endpoint_context.provider_info)

        # The client not registered and the OP not supporting automatic client registration
        with pytest.raises(OtherError):
            self.service['authorization'].construct()
