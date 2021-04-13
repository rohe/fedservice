from oidcop import user_info
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.discovery import Discovery
from oidcop.oidc.token import Token
from oidcop.oidc.userinfo import UserInfo
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

from oidcop.util import JSONDictDB

from fedservice.op import service

KEYDEFS = [{"type": "RSA", "key": '', "use": ["sig"]},
           {"type": "EC", "crv": "P-256", "use": ["sig"]}]

RESPONSE_TYPES_SUPPORTED = [
    ["code"], ["token"], ["id_token"], ["code", "token"], ["code", "id_token"],
    ["id_token", "token"], ["code", "token", "id_token"], ['none']]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "response_modes_supported": ['query', 'fragment', 'form_post'],
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code", "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer", "refresh_token"],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

BASE_URL = "https://127.0.0.1:8102/"

CONFIG = {
    'provider': {
        'key_defs': [
            {"type": "RSA", "use": ["sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"]}
        ],
    },
    'server_info': {
        "issuer": BASE_URL,
        "password": "mycket hemlig information",
        "token_expires_in": 600,
        "grant_expires_in": 300,
        "refresh_token_expires_in": 86400,
        "verify_ssl": False,
        "capabilities": CAPABILITIES,
        'template_dir': 'templates',
        "jwks": {
            'private_path': 'own/jwks.json',
            'key_defs': KEYDEFS,
            'public_path': 'static/jwks.json'
        },
        'endpoint': {
            'webfinger': {
                'path': '{}/.well-known/webfinger',
                'class': Discovery,
                'kwargs': {'client_authn_method': None}
            },
            'provider_info': {
                'path': '{}/.well-known/openid-federation',
                'class': service.ProviderConfiguration,
                'kwargs': {'client_authn_method': None}
            },
            'federation_registration': {
                'path': '{}/registration',
                'class': service.Registration,
                'kwargs': {'client_authn_method': None}
            },
            'authorization': {
                'path': '{}/authorization',
                'class': Authorization,
                'kwargs': {'client_authn_method': None}
            },
            'token': {
                'path': '{}/token',
                'class': Token,
                'kwargs': {}
            },
            'userinfo': {
                'path': '{}/userinfo',
                'class': UserInfo,
            }
        },
        'userinfo': {
            'class': user_info.UserInfo,
            'kwargs': {'db_file': 'users.json'}
        },
        'authentication': [
            {
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'UserPassJinja2',
                'kwargs': {
                    'template': 'user_pass.jinja2',
                    'db': {
                        'class': JSONDictDB,
                        'kwargs':
                            {'json_path': 'passwd.json'}
                    },
                    'page_header': "Testing log in",
                    'submit_btn': "Get me in!",
                    'user_label': "Nickname",
                    'passwd_label': "Secret sauce"
                }
            },
            {
                'acr': 'anon',
                'name': 'NoAuthn',
                'kwargs': {'user': 'diana'}
            }
        ],
        'cookie_dealer': {
            'symkey': 'ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch',
            'cookie': {
                'name': 'fedoidc_op',
                'domain': "127.0.0.1",
                'path': '/',
                'max_age': 3600
            }
        },
        'federation': {
            'entity_id': BASE_URL,
            'signing_keys': {
                'private_path': './entity_keys.json',
                'key_defs': KEYDEFS,
                'public_path': './pub_entity_keys.json'
            },
            'authority_hints': 'authority_hints.json',
            'trusted_roots': 'trusted_roots.json',
            'priority': [],
            'entity_type': 'openid_provider',
            'opponent_entity_type': 'openid_client'
            # 'default_lifetime': 86400
        }
    },
    'webserver': {
        'cert': 'certs/cert.pem',
        'key': 'certs/key.pem',
        'cert_chain': '',
        'port': 8102,
    }
}
