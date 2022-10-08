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
from fedservice.entity.server.resolve import Resolve
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
RESOLVER_ID = "https://resolver.example.org"
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

RESOLVER_CONFIG = copy.deepcopy(LEAF_CONFIG)
RESOLVER_CONFIG["entity_id"] = RESOLVER_ID
RESOLVER_CONFIG["httpc_params"] = {"verify": False, "timeout": 1}
RESOLVER_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "authority_hints": [TA_ID],
    "organization_name": "The example resolver",
    "homepage_uri": "https://www.example.com",
    "contacts": "operations@resolver.example.com"
}

RESOLVER_CONFIG['federation_entity']['kwargs']['server']['kwargs']['endpoint']['resolver'] = {
    "path": "resolver",
    "class": Resolve,
    "kwargs": {}
}


#     Federation tree
#
#            TA
#        +---|-------+
#        |          |
#        IM      RESOLVER
#        |
#        RP

def create_trust_chain_messages(leaf, *entity):
    where_and_what = {}

    if isinstance(leaf, str):
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
        _config = RESOLVER_CONFIG.copy()
        _config['federation_entity']['kwargs']['function']['kwargs'][
            'functions']['trust_chain_collector']['kwargs']['trust_anchors'] = ANCHOR
        self.resolver = FederationCombo(_config)

        _trust_anchor_federation_entity_server = self.ta['federation_entity'].server
        _trust_anchor_federation_entity_server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        _trust_anchor_federation_entity_server.subordinate[RESOLVER_ID] = {
            "jwks": self.resolver.keyjar.export_jwks(),
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
        assert set(self.ta['federation_entity'].server.subordinate.keys()) == {RESOLVER_ID, IM_ID}

    def test_resolver(self):
        _resolver = self.resolver['federation_entity']
        resolver = _resolver.server.endpoint["resolve"]

        where_and_what = create_trust_chain_messages(self.rp, self.im, self.ta)

        resolver_query = {'sub': self.rp["federation_entity"].entity_id,
                          'anchor': self.ta['federation_entity'].entity_id}

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            response = resolver.process_request(resolver_query)

        assert response

