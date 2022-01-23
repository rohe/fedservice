# https://127.0.0.1:6001/.well-known/openid-federation
# https://127.0.0.1:6001/list
# https://127.0.0.1:6001/fetch

# first the self signed entity statement
import json
import sys
from urllib.parse import urlencode

from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
import requests

from fedservice.message import EntityStatement


def get_self_signed_entity_statement(entity_id):
    _url = entity_id + "/.well-known/openid-federation"
    _response = requests.request("GET", _url, verify=False)
    _jws = factory(_response.text)
    _payload = _jws.jwt.payload()
    entity_statement = EntityStatement(**_payload)
    _key_jar = KeyJar()
    # verify  entity_statement["iss"]
    _key_jar.import_jwks(entity_statement['jwks'], entity_id)
    _keys = _key_jar.get_jwt_verify_keys(_jws.jwt)
    _res = _jws.verify_compact(keys=_keys)
    return _res


def list_entities(list_endpoint):
    _response = requests.request("GET", list_endpoint, verify=False)
    _list = json.loads(_response.text)
    return _list


def fetch_entity(fetch_endpoint, iss, sub, iss_entity_statement):
    _response = requests.request("GET", fetch_endpoint, verify=False,
                                 params={'iss': iss, 'sub': sub})
    _jws = factory(_response.text)
    _key_jar = KeyJar()
    _key_jar.import_jwks(iss_entity_statement['jwks'], iss)
    _keys = _key_jar.get_jwt_verify_keys(_jws.jwt)
    _res = _jws.verify_compact(keys=_keys)
    return _res


if __name__ == "__main__":
    entity_id = sys.argv[1]
    _entity_statement = get_self_signed_entity_statement(entity_id)
    assert _entity_statement["iss"] == entity_id
    _list_endpoint = _entity_statement["metadata"]['federation_entity'].get(
        "federation_list_endpoint")
    _fetch_endpoint = _entity_statement["metadata"]['federation_entity'].get(
        "federation_fetch_endpoint")
    if _list_endpoint:
        _list = list_entities(_list_endpoint)
        for _entity in _list:
            _statement = fetch_entity(_fetch_endpoint, entity_id, _entity, _entity_statement)
