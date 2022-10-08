import copy

import pytest
import requests
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo

from fedservice.combo import FederationCombo
from fedservice.entity import FederationEntity
from fedservice.entity.client import FederationEntityClient
from fedservice.entity.client.entity_configuration import \
    EntityConfiguration as c_EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.entity_configuration import EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.entity.server.list import List
from fedservice.node import Collection
from fedservice.op import ServerEntity
from fedservice.op.authorization import Authorization
from fedservice.op.registration import Registration
from fedservice.rp import ClientEntity
from tests import CRYPT_CONFIG
from tests import RESPONSE_TYPES_SUPPORTED
from tests import SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

INTERMEDIATE_CONFIG = {
    # "entity_id": TA_ID,
    "key_conf": {"key_defs": KEYDEFS},
    "federation_entity": {
        'class': FederationEntity,
        "kwargs": {
            "server": {
                'class': FederationEntityServer,
                'kwargs': {
                    "metadata": {},
                    "endpoint": {
                        "entity_configuration": {
                            "path": ".well-known/openid-federation",
                            "class": EntityConfiguration,
                            "kwargs": {}
                        },
                        "fetch": {
                            "path": "fetch",
                            "class": Fetch,
                            "kwargs": {}
                        },
                        "list": {
                            "path": "list",
                            "class": List,
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    }
}

TA_CONFIG = INTERMEDIATE_CONFIG.copy()
TA_CONFIG["entity_id"] = TA_ID
TA_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "organization_name": "The example cooperation",
    "homepage_uri": "https://www.example.com",
    "contacts": "operations@example.com"
}

IM_CONFIG = INTERMEDIATE_CONFIG.copy()
IM_CONFIG["entity_id"] = IM_ID
IM_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "authority_hints": [TA_ID],
    "organization_name": "The example cooperation",
    "homepage_uri": "https://www.example.com",
    "contacts": "ops@example.com"
}

LEAF_CONFIG = {
    # "entity_id": *_ID,
    "key_conf": {"key_defs": KEYDEFS},
    "federation_entity": {
        'class': FederationEntity,
        "kwargs": {
            "function": {
                'class': Collection,
                'kwargs': {
                    'functions': {
                        "trust_chain_collector": {
                            "class": TrustChainCollector,
                            "kwargs": {
                                # "trust_anchors": ANCHOR,
                                "allowed_delta": 600
                            }
                        },
                        'verifier': {
                            'class': TrustChainVerifier,
                            'kwargs': {}
                        },
                        'policy': {
                            'class': TrustChainPolicy,
                            'kwargs': {}
                        }
                    }
                }
            },
            "client": {
                'class': FederationEntityClient,
                'kwargs': {
                    "services": {
                        "entity_configuration": {
                            "class": c_EntityConfiguration,
                            "kwargs": {}
                        },
                        "entity_statement": {
                            "class": EntityStatement,
                            "kwargs": {}
                        }
                    }
                }
            },
            "server": {
                'class': FederationEntityServer,
                'kwargs': {
                    "metadata": {
                        # "authority_hints": [TA_ID],
                        # "organization_name": "The example",
                        # "homepage_uri": "https://www.example.com",
                        # "contacts": "app@rp.example.com"
                    },
                    "endpoint": {
                        "entity_configuration": {
                            "path": ".well-known/openid-federation",
                            "class": EntityConfiguration,
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    }
}

RP_CONFIG = copy.deepcopy(LEAF_CONFIG)
RP_CONFIG["entity_id"] = RP_ID
RP_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "authority_hints": [IM_ID],
    "organization_name": "The example",
    "homepage_uri": "https://www.example.com",
    "contacts": "app@rp.example.com"
}
RP_CONFIG['openid_relying_party'] = {
    'class': ClientEntity,
    'kwargs': {
        "config": {
            "redirect_uris": [f"{RP_ID}/authz_cb"],
            "behaviour": {"response_types": ["code"]},
            "key_conf": {"key_defs": KEYDEFS},
            "services": {
                "discovery": {
                    "class": "fedservice.rp.provider_info_discovery.FedProviderInfoDiscovery",
                    "kwargs": {}
                },
                "registration": {
                    "class": "fedservice.rp.registration.Registration",
                    "kwargs": {}
                },
                "authorization": {
                    "class": "fedservice.rp.authorization.FedAuthorization",
                    "kwargs": {}
                }
            }
        }
    }
}

OP_CONFIG = copy.deepcopy(LEAF_CONFIG)
OP_CONFIG["entity_id"] = OP_ID
OP_CONFIG["httpc_params"] = {"verify": False, "timeout": 1}
OP_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "authority_hints": [TA_ID],
    "organization_name": "The example identity provider",
    "homepage_uri": "https://www.example.com",
    "contacts": "operations@op.example.com"
}
OP_CONFIG['openid_provider'] = {
    'class': ServerEntity,
    'kwargs': {
        "config": {
            # "issuer": "https://example.com/",
            "capabilities": {
                "subject_types_supported": ["public", "pairwise", "ephemeral"],
                "grant_types_supported": [
                    "authorization_code",
                    "implicit",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "refresh_token",
                ],
            },
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
                },
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "id_token": {
                    "class": "idpyoidc.server.token.id_token.IDToken",
                    "kwargs": {
                        "base_claims": {
                            "email": {"essential": True},
                            "email_verified": {"essential": True},
                        }
                    },
                },
            },
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {"keys": {"key_defs": COOKIE_KEYDEFS}},
            },
            "keys": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
            "endpoint": {
                "registration": {
                    "path": "registration",
                    "class": Registration,
                    "kwargs": {"client_auth_method": None},
                },
                "authorization": {
                    "path": "authorization",
                    "class": Authorization,
                    "kwargs": {
                        "response_types_supported": [" ".join(x) for x in
                                                     RESPONSE_TYPES_SUPPORTED],
                        "response_modes_supported": ["query", "fragment", "form_post"],
                        "claim_types_supported": [
                            "normal",
                            "aggregated",
                            "distributed",
                        ],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                    },
                },
                "token": {
                    "path": "token",
                    "class": Token,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
                "userinfo": {"path": "userinfo", "class": UserInfo, "kwargs": {}},
            },
            "template_dir": "template",
            "session_params": SESSION_PARAMS,
        }
    }
}


#              TA
#          +---|---+
#          |       |
#          IM      OP
#          |
#          RP

def create_trust_chain_messages(leaf, *entity):
    where_and_what = {}

    if isinstance(leaf,str):
        pass
    else:
        _endpoint = leaf['federation_entity'].server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

    for n in range(0, len(entity)):
        ent = entity[n]
        _endpoint = ent['federation_entity'].server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

        _endpoint = ent['federation_entity'].server.get_endpoint('fetch')
        if n == 0:
            if isinstance(leaf, str):
                _sub = leaf
            else:
                _sub = leaf.entity_id
        else:
            _sub = entity[n - 1].entity_id
        _req = _endpoint.parse_request({'iss': ent.entity_id, 'sub': _sub})
        where_and_what[_endpoint.full_path] = _endpoint.process_request(_req)["response"]

    return where_and_what


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        # TRUST ANCHOR
        self.ta = FederationCombo(TA_CONFIG, httpc=requests)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks_as_json()}

        # Intermediate
        self.im = FederationCombo(IM_CONFIG, httpc=requests)

        # Leaf RP
        _config = RP_CONFIG.copy()
        _config['federation_entity']['kwargs']['function']['kwargs'][
            'functions']['trust_chain_collector']['kwargs']['trust_anchors'] = ANCHOR
        self.rp = FederationCombo(_config)

        # Leaf OP
        _config = OP_CONFIG.copy()
        _config['federation_entity']['kwargs']['function']['kwargs'][
            'functions']['trust_chain_collector']['kwargs']['trust_anchors'] = ANCHOR
        self.op = FederationCombo(_config)

        _trust_anchor_federation_entity_server = self.ta['federation_entity'].server
        _trust_anchor_federation_entity_server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        _trust_anchor_federation_entity_server.subordinate[OP_ID] = {
            "jwks": self.op.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        _im_federation_entity_server = self.im['federation_entity'].server
        _im_federation_entity_server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'authority_hints': [IM_ID]
        }

    def test_setup(self):
        assert self.ta
        assert self.ta['federation_entity'].server
        assert set(self.ta['federation_entity'].server.subordinate.keys()) == {OP_ID, IM_ID}

    def test_provider_info_discovery(self):
        _rp = self.rp['openid_relying_party']
        _rp._service_context.issuer = self.op.entity_id
        provider_info = _rp.get_service('provider_info')

        # Just to verify that the request URL is the right one
        req = provider_info.get_request_parameters()
        assert req['url'] == 'https://op.example.org/.well-known/openid-federation?iss=https%3A%2F%2Fop.example.org'

        where_and_what = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            trust_chains = _rp.do_request('provider_info')

        assert len(trust_chains) == 1
        assert set(trust_chains[0].metadata.keys()) == {'federation_entity', 'openid_provider'}

    def test_create_explicit_registration_request(self):
        # phase 1 : the RP gathers the OpenID Providers metadata
        _rp = self.rp['openid_relying_party']
        _rp._service_context.issuer = self.op.entity_id
        provider_info = _rp.get_service('provider_info')

        # Just to verify that the request URL is the right one
        req = provider_info.get_request_parameters()
        assert req['url'] == 'https://op.example.org/.well-known/openid-federation?iss=https%3A%2F%2Fop.example.org'

        where_and_what = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _rp.do_request('provider_info')

        # Phase 2: The RP creates a registration request
        _rp = self.rp['openid_relying_party']
        _registration = _rp.get_service('registration')

        req = _registration.get_request_parameters()
        assert req['url'] == 'https://op.example.org/registration'

        where_and_what = create_trust_chain_messages(self.rp.entity_id, self.im, self.ta)

        # Phase 3: The OP receives a registration request and responds to it.

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _op = self.op['openid_provider']
            _endpoint = _op.get_endpoint('registration')
            resp = _endpoint.process_request(req['body'])

        assert resp['response_code'] == 201
        _jws = factory(resp['response_msg'])
        _payload = _jws.jwt.payload()
        assert _payload['iss'] == self.op.entity_id
        assert _payload['sub'] == self.rp.entity_id
        assert _payload['trust_anchor_id'] == self.ta.entity_id
        assert _payload['aud'] == self.rp.entity_id

        # This is cached
        del where_and_what[f"{self.ta.entity_id}/.well-known/openid-federation"]

        # Phase 4: The RP receives the registration response and calculates the metadata
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            reg_resp = _registration.parse_response(resp['response_msg'])

        assert reg_resp
        assert 'client_id' in reg_resp