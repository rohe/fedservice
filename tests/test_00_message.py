from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.time_util import utc_time_sans_frac

from fedservice.message import EntityStatement
from fedservice.message import Metadata
from fedservice.message import Policy


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
    metadata['openid_relying_party'] = client_info

    _mj = metadata.to_json()

    _metadata = Metadata().from_json(_mj)

    assert set(_metadata.keys()) == {'openid_relying_party'}
    assert set(_metadata['openid_relying_party'].keys()) == {
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
    metadata['openid_relying_party'] = client_info

    iat = utc_time_sans_frac()  # seconds since epoch
    exp = iat + 3600
    entity_statement = EntityStatement(metadata=metadata,
                                       iss='https://example.com',
                                       sub='https://foo.example.com',
                                       iat=iat, exp=exp)

    jes = entity_statement.to_json()

    _es = EntityStatement().from_json(jes)
    assert set(_es.keys()) == {'metadata', 'iss', 'sub', 'iat', 'exp'}
    assert set(_es['metadata'].keys()) == {'openid_relying_party'}
    assert set(_es['metadata']['openid_relying_party'].keys()) == {
        'application_type', 'claims', 'id_token_signing_alg_values_supported',
        'redirect_uris', 'response_types'}

MSG = {
  "exp": 1568397247,
  "iat": 1568310847,
  "iss": "https://edugain.geant.org",
  "jwks": {
    "keys": [
      {
        "e": "AQAB",
        "kid": "N1pQTzFxUXZ1RXVsUkVuMG5uMnVDSURGRVdhUzdO...",
        "kty": "RSA",
        "n": "3EQc6cR_GSBq9km9-WCHY_lWJZWkcn0M05TGtH6D9S..."
      }
    ]
  },
  "metadata_policy": {
    "openid_provider": {
      "contacts": {
        "add": "ops@edugain.geant.org"
      }
    },
    "openid_relying_party": {
      "contacts": {
        "add": "ops@edugain.geant.org"
      }
    }
  },
  "sub": "https://swamid.se"
}

def test_metadata_policy():
    item = EntityStatement(**MSG)
    assert item
    _metadata_policy = item["metadata_policy"]
    for typ, item in _metadata_policy.items():
        for attr, _policy in item.items():
            _p = Policy(**_policy)
            _p.verify()