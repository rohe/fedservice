from typing import List
from typing import Optional

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.utils import make_federation_combo

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         endpoints: Optional[list] = None,
         services: Optional[dict] = None,
         key_config: Optional[dict] = None,
         federation_services: Optional[list] = None):
    if not endpoints:
        endpoints = ["entity_configuration"],
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}
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
        services=federation_services,
        trust_anchors=trust_anchors,
        httpc_params={
            "verify": False,
            "timeout": 14
        },
        entity_type={
            "openid_relying_party": {
                'class': "fedservice.appclient.ClientEntity",
                'kwargs': {
                    'config': {
                        'client_id': entity_id,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "keys": {"uri_path": "static/jwks.json", "key_defs": DEFAULT_KEY_DEFS},
                        "preference": {
                            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                            "id_token_signed_response_alg": "ES256",
                            "token_endpoint_auth_method": "client_secret_basic",
                            "token_endpoint_auth_signing_alg": "ES256"
                        }
                    },
                    "services": services
                }
            }
        }
    )

    return entity
