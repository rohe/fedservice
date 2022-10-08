import copy

import pytest
import requests
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo
from idpyoidc.util import rndstr

from fedservice.combo import FederationCombo
from fedservice.entity import FederationEntity
from fedservice.entity.client import FederationEntityClient
from fedservice.entity.client.entity_configuration import \
    EntityConfiguration as c_EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.trust_mark_verifier import TrustMarkVerifier
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.entity_configuration import EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.entity.server.list import List
from fedservice.entity.server.status import TrustMarkStatus
from fedservice.entity_statement.trust_mark import create_trust_mark
from fedservice.node import Collection
from fedservice.rp import ClientEntity

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
TRUST_MARK_ISSUER_ID = "https://trust_mark_issuer.example.org"
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
                        },
                        'trust_mark_verifier': {
                            'class': TrustMarkVerifier,
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

TRUST_MARK_ISSUER_CONFIG = copy.deepcopy(LEAF_CONFIG)
TRUST_MARK_ISSUER_CONFIG["entity_id"] = TRUST_MARK_ISSUER_ID
TRUST_MARK_ISSUER_CONFIG["httpc_params"] = {"verify": False, "timeout": 1}
TRUST_MARK_ISSUER_CONFIG['federation_entity']['kwargs']['server']['kwargs']['metadata'] = {
    "authority_hints": [TA_ID],
    "organization_name": "The example trust mark issuer",
}

TRUST_MARK_ISSUER_CONFIG[
    'federation_entity']['kwargs']['server']['kwargs']['endpoint']['status'] = {
    "path": "status",
    "class": TrustMarkStatus,
    "kwargs": {}
}


#     Federation tree
#
#            TA
#        +---|-------+
#        |           |
#        IM      TRUST_MARK_ISSUER
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
        _config = TRUST_MARK_ISSUER_CONFIG.copy()
        _config['federation_entity']['kwargs']['function']['kwargs'][
            'functions']['trust_chain_collector']['kwargs']['trust_anchors'] = ANCHOR
        self.tmi = FederationCombo(_config)

        _trust_anchor_federation_entity_server = self.ta['federation_entity'].server
        _trust_anchor_federation_entity_server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        _trust_anchor_federation_entity_server.subordinate[TRUST_MARK_ISSUER_ID] = {
            "jwks": self.tmi.keyjar.export_jwks(),
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
        assert set(self.ta['federation_entity'].server.subordinate.keys()) == {TRUST_MARK_ISSUER_ID,
                                                                               IM_ID}

    def test_trust_mark_verifier(self):
        _rpfe = self.rp['federation_entity']

        where_and_what = create_trust_chain_messages(self.tmi, self.ta)

        _trust_mark = create_trust_mark(self.tmi.entity_id,
                                        self.tmi.keyjar,
                                        trust_mark_id=rndstr(),
                                        subject=self.rp.entity_id,
                                        lifetime=10,
                                        reference='https://refeds.org/sirtfi')

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = _rpfe.function.trust_mark_verifier(_trust_mark)

        assert verified_trust_mark
