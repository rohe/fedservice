from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar

from fedservice.entity_statement.create import create_entity_statement
from fedservice.keyjar import import_jwks_as_json

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

RECEIVER = 'https://example.org/op'


def test_create_self_signed():
    metadata = {
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
    }

    iss = "https://example.com"
    sub = iss

    key_jar = build_keyjar(KEYSPEC, issuer_id=iss)
    authority = ["https://ntnu.no"]

    _jwt = create_entity_statement(iss, sub, key_jar, metadata=metadata, authority_hints=authority)

    assert _jwt

    _verifier = factory(_jwt)
    keys = key_jar.get_jwt_verify_keys(_verifier.jwt)
    res = _verifier.verify_compact(keys=keys)

    assert res
    assert res['iss'] == iss
    assert res['sub'] == sub
    assert set(res.keys()) == {'metadata', 'iss', 'exp', 'sub', 'iat',
                               'authority_hints', 'jwks'}


def test_signed_someone_else_metadata():
    metadata = {
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
    }

    iss = "https://example.com"
    sub = "https://foo.example.org/rp"

    sub_key_jar = build_keyjar(KEYSPEC, issuer_id=sub)

    iss_key_jar = build_keyjar(KEYSPEC, issuer_id=iss)

    iss_key_jar = import_jwks_as_json(iss_key_jar,
                                      sub_key_jar.export_jwks_as_json(issuer_id=sub),
                                      sub)

    sub_key_jar = import_jwks_as_json(sub_key_jar,
                                      iss_key_jar.export_jwks_as_json(issuer_id=iss),
                                      iss)

    authority = {"https://core.example.com": ["https://federation.example.org"]}

    _jwt = create_entity_statement(iss, sub, iss_key_jar, metadata=metadata,
                                   authority_hints=authority)

    assert _jwt

    _verifier = factory(_jwt)
    keys = sub_key_jar.get_jwt_verify_keys(_verifier.jwt)
    res = _verifier.verify_compact(keys=keys)

    assert res
    assert res['iss'] == iss
    assert res['sub'] == sub
    assert set(res.keys()) == {'metadata', 'iss', 'exp', 'sub', 'iat',
                               'authority_hints', 'jwks'}
