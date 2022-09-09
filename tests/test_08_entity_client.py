from idpyoidc.util import instantiate

from fedservice.entity.client import FederationEntityClient
from fedservice.entity.client.entity_configuration import EntityConfiguration
from fedservice.entity.client.entity_statement import EntityStatement

OPPONENT_ID = "https://example.org"
TENNANT_ID = "https://example.org/tennant1"
ENTITY_ID = "https://entity.example.org"
ISSUER = "https://example.org/adm1"


def test_entity_configuration():
    conf = {
        "services": {
            "entity_configuration": {
                "class": EntityConfiguration,
                "kwargs": {}
            },
            "entity_statement": {
                "class": EntityStatement,
                "kwargs": {}
            }
        }
    }

    entity = instantiate(FederationEntityClient, config=conf)
    _serv = entity.get_service('entity_configuration')
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


def test_entity_statement():
    conf = {
        "services": {
            "entity_configuration": {
                "class": EntityConfiguration,
                "kwargs": {}
            },
            "entity_statement": {
                "class": EntityStatement,
                "kwargs": {}
            }
        }
    }

    entity = instantiate(FederationEntityClient, config=conf)
    _serv = entity.get_service('entity_statement')
    _res = _serv.get_request_parameters(fetch_endpoint=f"{OPPONENT_ID}/fetch")
    assert _res == {
        'method': 'GET',
        'url': 'https://example.org/fetch'
    }
    _res = _serv.get_request_parameters(fetch_endpoint=f"{OPPONENT_ID}/fetch", issuer=ENTITY_ID)
    assert _res == {
        'method': 'GET',
        'url': 'https://example.org/fetch?iss=https%3A%2F%2Fentity.example.org'
    }

    _res = _serv.get_request_parameters(fetch_endpoint=f"{OPPONENT_ID}/fetch", issuer=ISSUER,
                                        subject=ENTITY_ID)
    assert _res == {
        'method': 'GET',
        'url': 'https://example.org/fetch?iss=https%3A%2F%2Fexample.org%2Fadm1&sub=https%3A%2F'
               '%2Fentity.example.org'
    }
