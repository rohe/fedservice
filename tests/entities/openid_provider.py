from typing import List
from typing import Optional

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.utils import make_federation_combo
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["id_token"],
    ["code", "id_token"]
]


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         endpoints: Optional[list] = None):
    if preference is None:
        preference = {
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        }

    entity = make_federation_combo(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        endpoints=endpoints,
        trust_anchors=trust_anchors,
        httpc_params={
            "verify": False,
            "timeout": 14
        },
        entity_type={
            "openid_provider": {
                'class': "fedservice.appserver.ServerEntity",
                'kwargs': {
                    "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    'config': {
                        "issuer": entity_id,
                        "metadata_schema": "fedservice.message.OPMetadata",
                        "httpc_params": {"verify": False, "timeout": 1},
                        "preference": {
                            "subject_types_supported": ["public", "pairwise", "ephemeral"],
                            "grant_types_supported": [
                                "authorization_code",
                                "implicit",
                                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                "refresh_token",
                            ],
                        },
                        "token_handler_args": {
                            "jwks_def": {
                                "private_path": "private/token_jwks.json",
                                "read_only": False,
                                "key_defs": [
                                    {"type": "oct", "bytes": "24", "use": ["enc"],
                                     "kid": "code"}],
                            },
                            "code": {
                                "lifetime": 600,
                                "kwargs": {
                                    "crypt_conf": CRYPT_CONFIG
                                }
                            },
                            "token": {
                                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                                "kwargs": {
                                    "lifetime": 3600,
                                    "add_claims_by_scope": True,
                                },
                            },
                            "refresh": {
                                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                                "kwargs": {
                                    "lifetime": 3600,
                                },
                            },
                            "id_token": {
                                "class": "idpyoidc.server.token.id_token.IDToken",
                                "kwargs": {
                                    "base_claims": {
                                        "email": {"essential": True},
                                        "email_verified": {"essential": True},
                                    }
                                },
                            },
                        },
                        "endpoint": {
                            "registration": {
                                "path": "registration",
                                "class": "fedservice.appserver.oidc.registration.Registration",
                                "kwargs": {"client_auth_method": None},
                            },
                            "authorization": {
                                "path": "authorization",
                                "class": "fedservice.appserver.oidc.authorization.Authorization",
                                "kwargs": {
                                    "response_types_supported": [" ".join(x) for x in
                                                                 RESPONSE_TYPES_SUPPORTED],
                                    "response_modes_supported": ["query", "fragment",
                                                                 "form_post"],
                                    "claim_types_supported": [
                                        "normal",
                                        "aggregated",
                                        "distributed",
                                    ],
                                    "claims_parameter_supported": True,
                                    "request_parameter_supported": True,
                                    "request_uri_parameter_supported": True,
                                },
                            },
                            "token": {
                                "path": "token",
                                "class": "idpyoidc.server.oidc.token.Token",
                                "kwargs": {
                                    "client_authn_method": [
                                        "client_secret_post",
                                        "client_secret_basic",
                                        "client_secret_jwt",
                                        "private_key_jwt",
                                    ]
                                }
                            },
                            "userinfo": {
                                "path": "userinfo",
                                "class": "idpyoidc.server.oidc.userinfo.UserInfo",
                                "kwargs": {}
                            },
                        },
                        "template_dir": "template",
                        "session_params": SESSION_PARAMS,
                    }
                }
            }
        }
    )

    return entity
