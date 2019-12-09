from oidcendpoint import user_info
from oidcendpoint.cookie import CookieDealer
from oidcendpoint.oidc.discovery import Discovery
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc.userinfo import UserInfo
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn
from oidcendpoint.user_authn.user import UserPassJinja2
from oidcendpoint.util import JSONDictDB

from fedservice.op import authorization
from fedservice.op import provider_config
from fedservice.op import registration as fed_registration

SESSION_COOKIE_NAME = 'floop'

RESPONSE_TYPES_SUPPORTED = [
    ["code"], ["token"], ["id_token"], ["code", "token"], ["code", "id_token"],
    ["id_token", "token"], ["code", "token", "id_token"], ['none']]

CAPABILITIES = {
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code", "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer", "refresh_token"],
}

KEY_DEF = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

PORT = 5000
DOMAIN = '127.0.0.1'
SERVER_NAME = '{}:{}'.format(DOMAIN, str(PORT))
BASE_URL = 'https://{}'.format(SERVER_NAME)

PATH = {
    'userinfo:kwargs:db_file': '{}/users.json',
    'authentication:user:kwargs:db:kwargs:json_path': '{}/passwd.json'
}

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
            'private_path': 'private/jwks.json',
            'key_defs': KEY_DEF,
            'public_path': 'static/jwks.json'
        },
        'endpoint': {
            'webfinger': {
                'path': '.well-known/webfinger',
                'class': Discovery,
                'kwargs': {'client_authn_method': None}
            },
            'provider_info': {
                'path': '.well-known/openid-federation',
                'class': provider_config.ProviderConfiguration,
                'kwargs': {'client_authn_method': None}
            },
            'registration': {
                'path': 'registration',
                'class': Registration,
                'kwargs': {'client_authn_method': None}
            },
            'federation_registration': {
                'path': 'fed_registration',
                'class': fed_registration.Registration,
                'kwargs': {'client_authn_method': None}
            },
            'authorization': {
                'path': 'authorization',
                'class': authorization.Authorization,
                'kwargs': {
                    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
                    "response_modes_supported": ['query', 'fragment', 'form_post'],
                    "claims_parameter_supported": True,
                    "request_parameter_supported": True,
                    "request_uri_parameter_supported": True,
                }
            },
            'token': {
                'path': 'token',
                'class': AccessToken,
                'kwargs': {
                    "client_authn_method": [
                        "client_secret_post", "client_secret_basic",
                        "client_secret_jwt", "private_key_jwt"],
                }
            },
            'userinfo': {
                'path': 'userinfo',
                'class': UserInfo,
                "kwargs": {
                    "claim_types_supported": ["normal", "aggregated", "distributed"],
                }
            }
        },
        'userinfo': {
            'class': user_info.UserInfo,
            'kwargs': {'db_file': 'users.json'}
        },
        'authentication': {
            "user": {
                'acr': INTERNETPROTOCOLPASSWORD,
                'class': UserPassJinja2,
                'verify_endpoint': 'verify/user',
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
            "anon": {
                'acr': UNSPECIFIED,
                'class': NoAuthn,
                'kwargs': {'user': 'diana'}
            }
        },
        'cookie_dealer': {
            'class': CookieDealer,
            'sign_jwk': 'private/cookie_sign_jwk.json',
            'sign_alg': 'SHA256',
            'default_values': {
                'name': 'oidc_op',
                'domain': DOMAIN,
                'path': '/',
                'max_age': 3600
            }
        },
        'federation': {
            'entity_id': BASE_URL,
            'signing_keys': {
                'private_path': 'fed_keys.json',
                'key_defs': KEY_DEF,
                'public_path': 'pub_fed_keys.json'
            },
            'authority_hints': 'authority_hints.json',
            'trusted_roots': 'trusted_roots.json',
            'priority': [],
            'entity_type': 'openid_provider',
            'opponent_entity_type': 'openid_relying_party'
            # 'default_lifetime': 86400
        }
    },
    'webserver': {
        'cert': '{}/certs/cert.pem',
        'key': '{}/certs/key.pem',
        'cert_chain': '',
        'port': PORT,
    }
}
