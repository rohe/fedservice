import os

from cryptojwt.jws.jws import factory
from oidcmsg.oidc import RegistrationResponse

from fedservice.message import EntityStatement
from fedservice.metadata_api.fs import make_entity_statement

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_config_information():
    res = make_entity_statement(
        root_dir=os.path.join(BASE_PATH, 'base_data'),
        iss='foodle.uninett.no',
        sub='foodle.uninett.no')
    _jws = factory(res)
    assert _jws
    payload = _jws.jwt.payload()
    assert payload['iss'] == 'https://foodle.uninett.no'
    assert payload['sub'] == 'https://foodle.uninett.no'

    es = EntityStatement().from_dict(payload)
    _item = es['metadata']['openid_relying_party']
    assert isinstance(_item, RegistrationResponse)
    assert _item['response_types'] == ['code']


def test_make_entity_statement():
    res = make_entity_statement(
        root_dir=os.path.join(BASE_PATH, 'base_data'),
        iss='ntnu.no',
        sub='foodle.uninett.no')
    _jws = factory(res)
    assert _jws
    payload = _jws.jwt.payload()
    assert payload['iss'] == 'https://ntnu.no'
    assert payload['sub'] == 'https://foodle.uninett.no'

    es = EntityStatement().from_dict(payload)
    _item = es['metadata_policy']['openid_relying_party']
    assert _item['contacts'] == {"add": 'ops@ntnu.no'}


