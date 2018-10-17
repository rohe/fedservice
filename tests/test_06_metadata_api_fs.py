import os

from cryptojwt.jws.jws import factory
from oidcmsg.oidc import RegistrationResponse

from fedservice.message import EntityStatement
from fedservice.metadata_api.fs import make_entity_statement

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_make_entity_statement():
    res = make_entity_statement(
        'https://127.0.0.1:6000', os.path.join(BASE_PATH, 'fedA'),
        iss='https://127.0.0.1:6000/com/rp')
    _jws = factory(res)
    assert _jws
    payload = _jws.jwt.payload()
    assert payload['iss'] == 'https://127.0.0.1:6000/com/rp'
    assert payload['sub'] == 'https://127.0.0.1:6000/com/rp'

    es = EntityStatement().from_dict(payload)
    _item = es['metadata']['openid_client']
    assert isinstance(_item, RegistrationResponse)
    assert _item['token_endpoint_auth_method'] == 'client_secret_basic'
