from oidcmsg.server.cookie_handler import CookieHandler

DOMAIN = 'op.umu.se'
BASE_URL = "https://{}".format(DOMAIN)

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]}
]

CONF = {
    'issuer': BASE_URL,
    'httpc_params': {'verify': False},
    'session_key': {
        'filename': 'private/umu_se_session_jwk.json',
        'type': 'OCT',
        'use': 'sig'},
    'capabilities': {
        'subject_types_supported': ['public', 'pairwise'],
        'grant_types_supported': ['authorization_code', 'implicit',
                                  'urn:ietf:params:oauth:grant-type:jwt-bearer',
                                  'refresh_token']},
    'template_dir': 'templates',
    'token_handler_args': {
        'jwks_def': {
            'private_path': 'private/umu_se_token_jwk.json',
            'read_only': False,
            'key_defs': [
                {'type': 'oct', 'bytes': 24, 'use': ['enc'], 'kid': 'code'},
                {'type': 'oct', 'bytes': 24, 'use': ['enc'], 'kid': 'refresh'}
            ]
        },
        'code': {'kwargs': {'lifetime': 600}},
        'token': {
            'class': 'oidcmsg.server.token.jwt_token.JWTToken',
            'kwargs': {
                'lifetime': 3600,
                'add_claims': ['email', 'email_verified',
                               'phone_number',
                               'phone_number_verified'],
                'add_claim_by_scope': True,
                'aud': ['https://example.org/appl']}
        },
        'refresh': {'kwargs': {'lifetime': 86400}},
        'id_token': {
            'class': 'oidcmsg.server.token.id_token.IDToken',
            'kwargs': {
                'default_claims': {'email': {'essential': True},
                                   'email_verified': {'essential': True}}}},
    },
    'keys': {
        'private_path': 'private/umu_se_jwks.json',
        'key_defs': [{'type': 'RSA', 'use': ['sig']},
                     {'type': 'EC', 'crv': 'P-256', 'use': ['sig']},
                     {'type': 'EC', 'crv': 'P-384', 'use': ['sig']}],
        'public_path': 'static/umu_se_jwks.json',
        'read_only': False,
        'uri_path': 'static/umu_se_jwks.json'
    },
    "cookie_handler": {
        "class": CookieHandler,
        "kwargs": {
            "keys": {"key_defs": COOKIE_KEYDEFS},
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_reg",
                "session_management": "oidc_op_sman"
            }
        },
    },
    'endpoint': {
        'webfinger': {
            'path': '.well-known/webfinger',
            'class': 'oidcmsg.server.oidc.discovery.Discovery'},
        'provider_info': {
            'path': '.well-known/openid-configuration',
            'class': 'oidcmsg.server.oidc.provider_config.ProviderConfiguration',
            'kwargs': {'client_authn_method': None}},
        'federation_info': {
            'path': '.well-known/openid-federation',
            'class': 'fedservice.op.provider_config.ProviderConfiguration',
            'kwargs': {'client_authn_method': None}},
        'federation_registration': {
            'path': 'registration',
            'class': 'fedservice.op.registration.Registration',
            'kwargs': {'client_authn_method': None}},
        'registration_api': {
            'path': 'registration_api',
            'class': 'oidcmsg.server.oidc.read_registration.RegistrationRead',
            'kwargs': {'client_authn_method': ['bearer_header']}},
        'introspection': {
            'path': 'introspection',
            'class': 'oidcmsg.server.oauth2.introspection.Introspection',
            'kwargs': {
                'client_authn_method': ['client_secret_post'],
                'release': ['username']}},
        'authorization': {
            'path': 'authorization',
            'class': 'fedservice.op.authorization.Authorization',
            'kwargs': {
                'client_authn_method': None,
                'claims_parameter_supported': True,
                'request_parameter_supported': True,
                'request_uri_parameter_supported': True,
                'response_types_supported': ['code', 'token',
                                             'id_token', 'code token',
                                             'code id_token',
                                             'id_token token',
                                             'code id_token token',
                                             'none'],
                'response_modes_supported': ['query', 'fragment', 'form_post']}
        },
        'pushed_authorization': {
            'path': 'pushed_authorization',
            'class': 'fedservice.op.pushed_authorization.PushedAuthorization',
            'kwargs': {
                'client_authn_method': ['client_secret_post', 'client_secret_basic',
                                        'client_secret_jwt', 'private_key_jwt']}
        },
        'token': {
            'path': 'token',
            'class': 'oidcmsg.server.oidc.token.Token',
            'kwargs': {
                'client_authn_method': ['client_secret_post', 'client_secret_basic',
                                        'client_secret_jwt', 'private_key_jwt']}},
        'userinfo': {
            'path': 'userinfo',
            'class': 'oidcmsg.server.oidc.userinfo.UserInfo',
            'kwargs': {
                'claim_types_supported': ['normal', 'aggregated', 'distributed']}},
        'end_session': {
            'path': 'session',
            'class': 'oidcmsg.server.oidc.session.Session',
            'kwargs': {'logout_verify_url': 'verify_logout',
                       'post_logout_uri_path': 'post_logout',
                       'signing_alg': 'ES256',
                       'frontchannel_logout_supported': True,
                       'frontchannel_logout_session_supported': True,
                       'backchannel_logout_supported': True,
                       'backchannel_logout_session_supported': True,
                       'check_session_iframe': 'check_session_iframe'}
        }
    },
    'userinfo': {
        'class': 'oidcmsg.server.user_info.UserInfo',
        'kwargs': {'db_file': 'users.json'}},
    'authentication': {
        'anon': {
            'acr': 'oidcmsg.server.user_authn.authn_context.UNSPECIFIED',
            'class': 'oidcmsg.server.user_authn.user.NoAuthn',
            'kwargs': {'user': 'diana'}}},
    'cookie_dealer': {
        'class': 'oidcmsg.server.cookie.CookieDealer',
        'sign_jwk': {
            'filename': 'private/cookie_sign_umu_jwk.json',
            'type': 'OCT',
            'kid': 'cookie_sign_key_id'
        },
        'kwargs': {
            'default_values': {
                'name': 'oidc_op',
                'domain': DOMAIN,
                'path': '/',
                'max_age': 3600}}},
    'login_hint2acrs': {
        'class': 'oidcmsg.server.login_hint.LoginHint2Acrs',
        'kwargs': {
            'scheme_map': {
                'email': [
                    'oidcmsg.server.user_authn.authn_context.INTERNETPROTOCOLPASSWORD']}}},
    'federation': {
        'entity_id': 'https://{}'.format(DOMAIN),
        'keys': {
            'private_path': 'base_data/op.umu.se/op.umu.se/jwks.json',
            'key_defs': [{'type': 'RSA', 'use': ['sig']},
                         {'type': 'EC', 'crv': 'P-256', 'use': ['sig']},
                         {'type': 'EC', 'crv': 'P-384', 'use': ['sig']}],
            'public_path': 'base_data/umu.se/op.umu.se/jwks.json',
            'read_only': False},
        "endpoint": {
            "fetch": {
                "path": "fetch",
                "class": 'fedservice.entity.fetch.Fetch',
                "kwargs": {"client_authn_method": None},
            }
        },
        'authority_hints': 'base_data/op.umu.se/op.umu.se/authority.json',
        'trusted_roots': 'trusted_roots.json',
        'priority': [],
        'entity_type': 'openid_provider',
        'opponent_entity_type': 'openid_relying_party'
    },
    'add_on': {
        'pkce': {
            'function': 'oidcmsg.server.oidc.add_on.pkce.add_pkce_support',
            'kwargs': {
                'essential': False,
                'code_challenge_method': ['S256', 'S384', 'S512']}},
        'claims': {
            'function': 'oidcmsg.server.oidc.add_on.custom_scopes.add_custom_scopes',
            'kwargs': {
                'research_and_scholarship': ['name', 'given_name', 'family_name',
                                             'email', 'email_verified', 'sub', 'iss',
                                             'eduperson_scoped_affiliation']}},
        'automatic_registration': {
            'function': 'fedservice.op.add_on.automatic_registration.add_support',
            'kwargs': {
                'new_id': False,
                'client_registration_authn_methods_supported': {
                    'ar': ['request_object']},
                'where': ['authorization']}
        }
    }
}
