import json
import os
import pytest
from idpyoidc.client.oidc import RP
from idpyoidc.client.oidc.authorization import Authorization

from fedservice.combo import Combo
from fedservice.entity import FederationEntity
from fedservice.entity.client import FederationEntityClient
from fedservice.entity.client.entity_configuration import \
    EntityConfiguration as c_EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement
from fedservice.entity.server import FederationEntityServer
from fedservice.entity.server.entity_configuration import \
    EntityConfiguration as s_EntityConfiguration
from fedservice.entity.server.fetch import Fetch
from fedservice.trust_mark_issuer.status import Status
from fedservice.trust_mark_issuer import TrustMarkIssuer

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()
ANCHOR = {'https://feide.no': json.loads(jwks)}

OPPONENT_ID = "https://example.org"
TENNANT_ID = "https://example.org/tennant1"
ENTITY_ID = "https://entity.example.org"
ISSUER = "https://example.org/adm1"
TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"


class TestEntityServer(object):
    @pytest.fixture(autouse=True)
    def server_setup(self):
        config = {
            "entity_id": ENTITY_ID,
            "key_conf": {"key_defs": KEYDEFS},
            "federation_entity": {
                'class': FederationEntity,
                "kwargs": {
                    "trusted_roots": ANCHOR,
                    "authority_hints": ['https://ntnu.no'],
                    "organization_name": "The example cooperation",
                    "homepage_uri": "https://www.example.com",
                    "contacts": "operations@example.com",
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
                            "endpoint": {
                                "entity_configuration": {
                                    "path": ".well-known/openid-federation",
                                    "class": s_EntityConfiguration,
                                    "kwargs": {}
                                },
                                "fetch": {
                                    "path": "fetch",
                                    "class": Fetch,
                                    "kwargs": {}
                                }
                            }
                        }
                    }
                }
            },
            "trust_issuer": {
                'class': TrustMarkIssuer,
                'kwargs': {
                    'config': {
                        "endpoint": {
                            "trust_mark_status": {
                                'path': 'status',
                                'class': Status,
                                'kwargs': {}
                            }
                        },
                        'trust_marks': {
                            TM_ID: {"ref": "https://refeds.org/sirtfi"}
                        }
                    }
                }
            },
            "openid_relying_party": {
                'class': RP,
                'kwargs': {
                    'config': {
                        "redirect_uris": ["https://example.com/cli/authz_cb"],
                        "client_id": "client_1",
                        "client_secret": "abcdefghijklmnop",
                        "key_conf": {"key_defs": KEYDEFS},
                        "add_ons": {
                            "pkce": {
                                "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                                "kwargs": {"code_challenge_length": 64,
                                           "code_challenge_method": "S256"},
                            }
                        },
                    }
                }
            }
        }

        self.entity = Combo(config)

    def test_federation_entity_client(self):
        assert self.entity

        _serv = self.entity["federation_entity"].client.get_service('entity_configuration')
        _res = _serv.get_request_parameters(request_args={"entity_id": OPPONENT_ID})
        assert _res == {
            'method': 'GET',
            'url': 'https://example.org/.well-known/openid-federation'
        }
        _res = _serv.get_request_parameters(request_args={"entity_id": TENNANT_ID}, tenant=True)
        assert _res == {
            'method': 'GET',
            'url': 'https://example.org/tennant1/.well-known/openid-federation'
        }

    def test_federation_entity_server(self):
        _endpoint = self.entity["federation_entity"].server.get_endpoint('entity_configuration')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args

    def test_trust_issuer(self):
        _trust_issuer = self.entity["trust_issuer"]
        # Issue a trust mark
        _tm = _trust_issuer.create_trust_mark(TM_ID, 'https://rp.example.com')

        _endpoint = _trust_issuer.get_endpoint("status")
        _req = _endpoint.parse_request({
            "sub": 'https://rp.example.com',
            "id": TM_ID
        })
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args

    def test_rp(self):
        rp = self.entity["openid_relying_party"]
        auth_serv = rp.client_get("service", "authorization")
        assert isinstance(auth_serv, Authorization)
        request = auth_serv.construct_request({"state": "STATE", "response_type": "code"},
                                              behaviour_args={"request_param": "request"})
        assert "request" in request

    def test_key_jars(self):
        # make sure the federation entity's key jar is different from the RP's
        assert self.entity.get_attribute("keyjar") != self.entity[
            "openid_relying_party"].get_attribute("keyjar")