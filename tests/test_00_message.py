from oidcmsg.oidc import RegistrationRequest
from oidcmsg.time_util import utc_time_sans_frac

from fedservice.message import EntityStatement
from fedservice.message import Metadata


def test_metadata():
    client_info = RegistrationRequest(**{
        "application_type": "web",
        "claims": [
            "sub",
            "name",
            "email",
            "picture"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS512"
        ],
        "redirect_uris": [
            "https://foodle.uninett.no/callback"
        ],
        "response_types": [
            "code"
        ]
    })
    metadata = Metadata()
    metadata['openid_client'] = client_info

    _mj = metadata.to_json()

    _metadata = Metadata().from_json(_mj)

    assert set(_metadata.keys()) == {'openid_client'}
    assert set(_metadata['openid_client'].keys()) == {
        'application_type', 'claims', 'id_token_signing_alg_values_supported',
        'redirect_uris', 'response_types'}


def test_entity_statement():
    client_info = RegistrationRequest(**{
        "application_type": "web",
        "claims": [
            "sub",
            "name",
            "email",
            "picture"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS512"
        ],
        "redirect_uris": [
            "https://foodle.uninett.no/callback"
        ],
        "response_types": [
            "code"
        ]
    })
    metadata = Metadata()
    metadata['openid_client'] = client_info

    iat = utc_time_sans_frac()  # seconds since epoch
    exp = iat + 3600
    entity_statement = EntityStatement(metadata=metadata,
                                       iss='https://example.com',
                                       sub='https://foo.example.com',
                                       iat=iat, exp=exp)

    jes = entity_statement.to_json()

    _es = EntityStatement().from_json(jes)
    assert set(_es.keys()) == {'metadata', 'iss', 'sub', 'iat', 'exp'}
    assert set(_es['metadata'].keys()) == {'openid_client'}
    assert set(_es['metadata']['openid_client'].keys()) == {
        'application_type', 'claims', 'id_token_signing_alg_values_supported',
        'redirect_uris', 'response_types'}
