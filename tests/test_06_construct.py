from fedservice.entity_statement.construct import map_configuration_to_preference

CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code", "id_token", "id_token token", "code id_token",
                       "code id_token token", "code token"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": "client_secret_basic"
}

ISS = 'https://example.com'

PROVIDER_INFO_RESPONSE = {
    "version": "3.0",
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": True,
    "grant_types_supported": ["authorization_code",
                              "implicit",
                              "urn:ietf:params:oauth:grant-type:jwt-bearer",
                              "refresh_token"],
    "response_types_supported": ["code", "id_token",
                                 "id_token token",
                                 "code id_token",
                                 "code token",
                                 "code id_token token"],
    "response_modes_supported": ["query", "fragment",
                                 "form_post"],
    "subject_types_supported": ["public", "pairwise"],
    "claim_types_supported": ["normal", "aggregated",
                              "distributed"],
    "claims_supported": ["birthdate", "address",
                         "nickname", "picture", "website",
                         "email", "gender", "sub",
                         "phone_number_verified",
                         "given_name", "profile",
                         "phone_number", "updated_at",
                         "middle_name", "name", "locale",
                         "email_verified",
                         "preferred_username", "zoneinfo",
                         "family_name"],
    "scopes_supported": ["openid", "profile", "email",
                         "address", "phone",
                         "offline_access", "openid"],
    "userinfo_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "id_token_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "request_object_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512", "none"],
    "token_endpoint_auth_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512"],
    "userinfo_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
        "ECDH-ES+A256KW"],
    "id_token_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
        "ECDH-ES+A256KW"],
    "request_object_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW",
        "A192KW", "A256KW", "ECDH-ES", "ECDH-ES+A128KW",
        "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "userinfo_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "id_token_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "request_object_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "acr_values_supported": ["PASSWORD"],
    "issuer": ISS,
    "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(ISS),
    "authorization_endpoint": "{}/authorization".format(ISS),
    "token_endpoint": "{}/token".format(ISS),
    "userinfo_endpoint": "{}/userinfo".format(ISS),
    "registration_endpoint": "{}/registration".format(ISS),
    "end_session_endpoint": "{}/end_session".format(ISS)
}


def test_map_configuration_to_preference():
    res = map_configuration_to_preference(PROVIDER_INFO_RESPONSE, CLIENT_PREFS)
    assert set(res.keys()) == {'application_type', 'application_name', 'contacts',
                               'response_types', 'scope', 'token_endpoint_auth_method'}
    assert isinstance(res["response_types"], list)
    assert isinstance(res["scope"], list)
