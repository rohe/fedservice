import copy
import os

from oidcmsg.client.exception import OtherError
import pytest
import responses

from fedservice.entity.fetch import Fetch
from fedservice.entity_statement.statement import TrustChain
from fedservice.fetch_entity_statement.fs2 import read_info
from fedservice.op import FederationServer
from fedservice.rp import FederationRP
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

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]}
]

ENTITY_ID = 'https://foodle.uninett.no'
OP_ENTITY_ID = "https://op.ntnu.no"

ANCHOR = {'https://feide.no': read_info(os.path.join(ROOT_DIR, 'feide.no'), "feide.no", "jwks")}

RP_CONFIG = {
    "issuer": OP_ENTITY_ID,
    'client_id': ENTITY_ID,
    'client_secret': 'a longesh password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYSPEC},
    "federation": {
        "entity_id": ENTITY_ID,
        "keys": {"uri_path": "static/fed_jwks.json",
                 "private_path": os.path.join(ROOT_DIR, 'foodle.uninett.no',
                                              'foodle.uninett.no', 'jwks.json')},
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

OP_CONF = {
    "issuer": OP_ENTITY_ID,
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "httpc_param": {'verify': False, "timeout": 2},
    "claims_interface": {"class": "oidcmsg.server.session.claims.ClaimsInterface", "kwargs": {}},
    "cookie_handler": {
        "class": "oidcmsg.server.cookie_handler.CookieHandler",
        "kwargs": {
            "keys": {
                "private_path": "private/cookie_jwks.json",
                "key_defs": [
                    {"type": "OCT", "use": ["enc"], "kid": "enc"},
                    {"type": "OCT", "use": ["sig"], "kid": "sig"},
                ],
                "read_only": False,
            },
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_rp",
                "session_management": "sman",
            },
        },
    },
    "endpoint": {
        'provider_info': {
            'path': '.well-known/openid-federation',
            'class': 'fedservice.op.provider_config.ProviderConfiguration',
            'kwargs': {'client_authn_method': None}
        },
        'registration': {
            'path': 'fed_registration',
            'class': 'fedservice.op.registration.Registration',
            'kwargs': {'client_authn_method': None}
        },
        'authorization': {
            'path': 'authorization',
            'class': 'fedservice.op.authorization.Authorization',
            'kwargs': {
                "response_modes_supported": ['query', 'fragment', 'form_post'],
                "claims_parameter_supported": True,
                "request_parameter_supported": True,
                "request_uri_parameter_supported": True,
                "client_authn_method": ['request_param']
            }
        }
    },
    "key_conf": {
        "private_path": "own/jwks.json",
        "uri_path": "static/jwks.json",
        "key_defs": KEYSPEC
    },
    "authentication": {
        "anon": {
            'acr': "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
            "class": 'oidcmsg.server.user_authn.user.NoAuthn',
            "kwargs": {"user": "diana"}
        }
    },
    'template_dir': 'template',
    "federation": {
        "entity_id": OP_ENTITY_ID,
        'keys': {'private_path': os.path.join(ROOT_DIR, 'op.ntnu.no', 'op.ntnu.no',
                                              'jwks.json')},
        "endpoint": {
            "fetch": {
                "path": "fetch",
                "class": 'fedservice.entity.fetch.Fetch',
                "kwargs": {"client_authn_method": None},
            }
        },
        "trusted_roots": ANCHOR,
        "authority_hints": ['https://ntnu.no'],
        "entity_type": 'openid_provider',
        "opponent_entity_type": 'openid_relying_party'
    }
}

HTTPC = Publisher(ROOT_DIR)


class TestExplicit(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        # First the RP

        entity = FederationRP(config=RP_CONFIG)

        _fe = entity.client_get("service_context").federation_entity
        # The test data collector
        _fe.collector = DummyCollector(
            trusted_roots=ANCHOR, httpd=HTTPC, root_dir=os.path.join(BASE_PATH, 'base_data'))

        # The RP has/supports 3 services
        self.service = {
            'discovery': FedProviderInfoDiscovery(entity.client_get),
            'registration': Registration(entity.client_get),
            'authorization': FedAuthorization(entity.client_get),
        }

        # and now for the OP

        server = FederationServer(OP_CONF, httpc=HTTPC)

        self.registration_endpoint = server.server_get("endpoint", "registration")
        self.authorization_endpoint = server.server_get("endpoint", "authorization")
        self.provider_endpoint = server.server_get("endpoint", "provider_config")

        # === Federation stuff =======
        federation_entity = server.server_get("endpoint_context").federation_entity
        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

    def test_explicit_registration(self):
        _registration_service = self.service['registration']
        # Using the RP's federation entity instance
        _fe = _registration_service.client_get("service_context").federation_entity

        _endpoint_context = self.registration_endpoint.server_get("endpoint_context")
        # This is cheating. Getting the OP provider info
        trust_chain = TrustChain()
        trust_chain.metadata = _endpoint_context.provider_info
        trust_chain.anchor = "https://feide.no"
        trust_chain.verified_chain = [{'iss': "https://ntnu.no"}]

        with responses.RequestsMock() as rsps:
            _jwks = self.authorization_endpoint.server_get(
                "endpoint_context").keyjar.export_jwks_as_json()
            rsps.add("GET", 'https://op.ntnu.no/static/jwks.json', body=_jwks,
                     adding_headers={"Content-Type": "application/json"}, status=200)

            self.service['discovery'].update_service_context([trust_chain])

        # Fake fetching the key from op.ntnu.no over the net
        _fe.context.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=_endpoint_context.provider_info['issuer'])

        # construct the client registration request
        req_args = {
            'entity_id': _fe.context.entity_id,
            'redirect_uris': ['https://foodle.uninett.no/cb']
        }
        _fe.context.proposed_authority_hints = ['https://ntnu.no']

        jws = _registration_service.construct(request_args=req_args)

        # THe OP handles the registration request

        res = self.registration_endpoint.process_request(jws)
        assert res

        reg_resp = self.registration_endpoint.do_response(**res)

        assert set(reg_resp.keys()) == {'response', 'response_code', 'http_headers', 'cookie'}

        # The RP parses the OP's response
        args = _registration_service.parse_response(reg_resp['response'], request=jws)
        assert set(args.keys()) == {'entity_id', 'client_id', 'contacts', 'application_type',
                                    'redirect_uris', 'response_types', 'client_id_issued_at',
                                    'client_secret', 'grant_types', 'client_secret_expires_at'}


class TestAutomatic(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        # First the RP
        _config = copy.deepcopy(RP_CONFIG)
        _config['behaviour'] = {
            'federation_types_supported': ['explicit']
        }
        entity = FederationRP(config=_config)
        self.rp_federation_entity = entity.client_get("service_context").federation_entity
        # The test data collector
        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, httpd=HTTPC, root_dir=os.path.join(BASE_PATH, 'base_data'))

        # The RP has/supports 3 services
        self.service = {
            'discovery': FedProviderInfoDiscovery(entity.client_get),
            'registration': Registration(entity.client_get),
            'authorization': FedAuthorization(entity.client_get,
                                              conf={"request_object_expires_in": 300}),
        }

        # and now for the OP
        _config = copy.copy(OP_CONF)
        _config['add_on'] = {
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
        server = FederationServer(_config)
        self.registration_endpoint = server.server_get("endpoint", "registration")
        self.authorization_endpoint = server.server_get("endpoint", "authorization")
        self.provider_endpoint = server.server_get("endpoint", "provider_config")

        federation_entity = server.server_get("endpoint_context").federation_entity
        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

    def test_automatic_registration_new_client_id(self):
        _registration_service = self.service['registration']

        self.authorization_endpoint.server_get("endpoint_context").provider_info[
            'client_registration_authn_methods_supported'] = {"ar": ['request_object']}
        self.authorization_endpoint.automatic_registration_endpoint.kwargs['new_id'] = True
        # This is cheating. Getting the OP's provider info
        _fe = _registration_service.client_get("service_context").federation_entity
        statement = TrustChain()
        statement.metadata = self.registration_endpoint.server_get("endpoint_context").provider_info
        statement.anchor = "https://feide.no"
        statement.verified_chain = [{'iss': "https://ntnu.no"}]

        with responses.RequestsMock() as rsps:
            _jwks = self.authorization_endpoint.server_get(
                "endpoint_context").keyjar.export_jwks_as_json()
            rsps.add("GET", 'https://op.ntnu.no/static/jwks.json', body=_jwks,
                     adding_headers={"Content-Type": "application/json"}, status=200)

            self.service['discovery'].update_service_context([statement])

        # and the OP's federation keys
        self.rp_federation_entity.context.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.server_get("endpoint_context").provider_info[
                'issuer'])

        _context = self.service['authorization'].client_get("service_context")
        _context.issuer = 'https://op.ntnu.no'
        _context.redirect_uris = ['https://foodle.uninett.no/callback']
        _context.entity_id = self.rp_federation_entity.context.entity_id
        _context.client_id = self.rp_federation_entity.context.entity_id
        _context.behaviour = {'response_types': ['code']}
        _context.provider_info = self.authorization_endpoint.server_get(
            "endpoint_context").provider_info
        authn_request = self.service['authorization'].construct()

        # Have to provide the OP with clients keys
        self.authorization_endpoint.server_get("endpoint_context").keyjar.import_jwks(
            _registration_service.client_get("service_context").keyjar.export_jwks(),
            ENTITY_ID
        )

        # The OP handles the authorization request
        req = self.authorization_endpoint.parse_request(authn_request.to_dict())
        assert "response_type" in req

        client_ids = list(self.authorization_endpoint.server_get("endpoint_context").cdb.keys())
        assert len(client_ids) == 2  # dynamic and entity_id
        assert ENTITY_ID in client_ids

    def test_automatic_registration_keep_client_id(self):
        # This is cheating. Getting the OP provider info
        _registration_service = self.service['registration']
        _fe = _registration_service.client_get("service_context").federation_entity
        statement = TrustChain()
        statement.metadata = self.registration_endpoint.server_get("endpoint_context").provider_info
        statement.anchor = "https://feide.no"
        statement.verified_chain = [{'iss': "https://ntnu.no"}]

        self.service['discovery'].update_service_context([statement])

        _fe_context = self.rp_federation_entity.get_context()
        # and the OP's federation keys
        _fe_context.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.server_get("endpoint_context").provider_info[
                'issuer'])

        service_context = self.service['authorization'].client_get("service_context")
        service_context.issuer = 'https://op.ntnu.no'
        service_context.redirect_uris = ['https://foodle.uninett.no/callback']
        service_context.entity_id = _fe_context.entity_id
        service_context.client_id = _fe_context.entity_id
        service_context.behaviour = {'response_types': ['code']}
        service_context.provider_info = self.authorization_endpoint.server_get(
            "endpoint_context").provider_info

        authn_request = self.service['authorization'].construct()
        # Have to provide the OP with clients keys
        self.authorization_endpoint.server_get("endpoint_context").keyjar.import_jwks(
            _registration_service.client_get("service_context").keyjar.export_jwks(),
            ENTITY_ID
        )

        _auth_endp_context = self.authorization_endpoint.server_get("endpoint_context")
        # get rid of the earlier client registrations
        for k in _auth_endp_context.cdb.keys():
            del _auth_endp_context.cdb[k]

        # Have to provide the OP with clients keys
        _auth_endp_context.keyjar.import_jwks(
            _registration_service.client_get("service_context").keyjar.export_jwks(),
            ENTITY_ID
        )

        # set new_id to False
        self.authorization_endpoint.automatic_registration_endpoint.kwargs["new_id"] = False

        # THe OP handles the authorization request
        req = self.authorization_endpoint.parse_request(authn_request.to_dict())
        assert "response_type" in req

        # reg_resp = self.registration_endpoint.do_response(**res)
        # assert set(reg_resp.keys()) == {'response', 'http_headers', 'cookie'}

        client_ids = list(_auth_endp_context.cdb.keys())
        assert len(client_ids) == 1
        assert client_ids[0] == ENTITY_ID


class TestAutomaticNoSupport(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        # First the RP
        _config = copy.deepcopy(RP_CONFIG)
        _config['behaviour'] = {
            'federation_types_supported': ['explicit']
        }
        entity = FederationRP(config=_config)
        self.rp_federation_entity = entity.client_get("service_context").federation_entity
        # The test data collector
        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=ANCHOR, httpd=HTTPC, root_dir=os.path.join(BASE_PATH, 'base_data'))

        entity._service = {
            'discovery': FedProviderInfoDiscovery(entity.client_get),
            'registration': Registration(entity.client_get),
            'authorization': FedAuthorization(entity.client_get,
                                              conf={"request_object_expires_in": 300}),
        }
        self.rp = entity

        # and now for the OP
        _config = copy.copy(OP_CONF)

        server = FederationServer(_config)
        self.registration_endpoint = server.server_get("endpoint", "registration")
        self.authorization_endpoint = server.server_get("endpoint", "authorization")
        self.provider_endpoint = server.server_get("endpoint", "provider_config")

        federation_entity = server.server_get("endpoint_context").federation_entity
        federation_entity.collector = DummyCollector(
            httpd=Publisher(ROOT_DIR),
            trusted_roots=ANCHOR,
            root_dir=ROOT_DIR)

    def test_automatic_registration_new_client_id(self):
        _registration_service = self.rp.get_service('registration')

        # This is cheating. Getting the OP's provider info
        _fe = _registration_service.client_get("service_context").federation_entity
        statement = TrustChain()
        statement.metadata = self.registration_endpoint.server_get("endpoint_context").provider_info
        statement.anchor = "https://feide.no"
        statement.verified_chain = [{'iss': "https://ntnu.no"}]

        self.rp.get_service('discovery').update_service_context([statement])
        # and the OP's federation keys
        self.rp_federation_entity.context.keyjar.import_jwks(
            read_info(os.path.join(ROOT_DIR, 'op.ntnu.no'), 'op.ntnu.no', 'jwks'),
            issuer_id=self.registration_endpoint.server_get("endpoint_context").provider_info[
                'issuer'])

        _context = self.rp.get_service('authorization').client_get("service_context")
        _context.issuer = 'https://op.ntnu.no'
        _context.redirect_uris = ['https://foodle.uninett.no/callback']
        _context.entity_id = self.rp_federation_entity.context.entity_id
        # _context.client_id = self.rp_federation_entity.entity_id
        _context.behaviour = {'response_types': ['code']}
        _context.provider_info = self.authorization_endpoint.server_get(
            "endpoint_context").provider_info

        # The client not registered and the OP not supporting automatic client registration
        with pytest.raises(OtherError):
            self.rp.get_service('authorization').construct()
