import os

from cryptojwt.jws.jws import factory

from fedservice.fetch_entity_statement.fs2 import FSFetchEntityStatement
from fedservice.message import EntityStatement
from fedservice.message import OIDCRPMetadata

BASE_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "base_data")


def test_config_information():
    fse = FSFetchEntityStatement(BASE_PATH, iss='foodle.uninett.no')
    _jwt = fse.create_entity_statement('foodle.uninett.no')
    _jws = factory(_jwt)
    assert _jws
    payload = _jws.jwt.payload()
    assert payload['iss'] == 'https://foodle.uninett.no'
    assert payload['sub'] == 'https://foodle.uninett.no'

    es = EntityStatement().from_dict(payload)
    _item = es['metadata']['openid_relying_party']
    assert isinstance(_item, OIDCRPMetadata)
    assert _item['response_types'] == ['code']


def test_make_entity_statement():
    fse = FSFetchEntityStatement(BASE_PATH, iss='ntnu.no')
    _statement = fse.create_entity_statement('foodle.uninett.no')
    _jws = factory(_statement)
    assert _jws
    payload = _jws.jwt.payload()
    assert payload['iss'] == 'https://ntnu.no'
    assert payload['sub'] == 'https://foodle.uninett.no'

    es = EntityStatement().from_dict(payload)
    _item = es['metadata_policy']['openid_relying_party']
    assert _item['contacts'] == {"add": 'ops@ntnu.no'}
