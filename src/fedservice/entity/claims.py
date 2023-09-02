from idpyoidc import metadata
from idpyoidc.claims import Claims as ClaimsBase
from idpyoidc.client.claims import oauth2 as OAuth2ClientClaims
from idpyoidc.client.claims import oidc as OIDCClientClaims
from idpyoidc.client.claims.transform import REGISTER2PREFERRED
from idpyoidc.server.claims import oauth2 as OAUTH2ServerClaims
from idpyoidc.server.claims import oidc as OIDCServerClaims

from fedservice import message


class OPClaims(OIDCServerClaims.Claims):
    _supports = OIDCServerClaims.Claims._supports.copy()
    _supports.update({
        'client_registration_types_supported': ['automatic', 'explicit'],
        'request_authentication_methods_supported': {
            "authorization_endpoint": [
                "request_object"
            ],
            "pushed_authorization_request_endpoint": [
                "request_object",
                "private_key_jwt"
            ]
        },
        'request_authentication_signing_alg_values_supported': metadata.get_signing_algs,
        'federation_registration_endpoint': None
    })

    def provider_info(self, supports):
        _info = {}
        for key in message.OPMetadataMessage.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info


class ASClaims(OAUTH2ServerClaims.Claims):
    _supports = OAUTH2ServerClaims.Claims._supports.copy()
    _supports.update({
        'client_registration_types_supported': ['automatic', 'explicit'],
        'request_authentication_methods_supported': {
            "authorization_endpoint": [
                "request_object"
            ],
            "pushed_authorization_request_endpoint": [
                "request_object",
                "private_key_jwt"
            ]
        },
        'request_authentication_signing_alg_values_supported': metadata.get_signing_algs,
        'federation_registration_endpoint': None
    })

    def verify_rules(self, **kwargs):
        pass

    def provider_info(self, supports):
        _info = {}
        for key in message.AuthorizationServerMetadata.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info


class RPClaims(OIDCClientClaims.Claims):
    _supports = OIDCClientClaims.Claims._supports.copy()

    register2preferred = OIDCClientClaims.REGISTER2PREFERRED
    registration_response = message.OIDCRPRegistrationResponse
    registration_request = message.OIDCRPMetadata


class ClientClaims(OAuth2ClientClaims.Claims):
    _supports = OAuth2ClientClaims.Claims._supports.copy()

    register2preferred = REGISTER2PREFERRED
    registration_response = message.OauthClientInformationResponse
    registration_request = message.OauthClientMetadata


class FederationEntityClaims(ClaimsBase):
    _supports = {
        'organization_name': None,
        'contacts': None,
        'policy_uri': None,
        'logo_uri': None,
        'homepage_uri': None,
        'trust_mark_owners': None,
        'trust_mark_issuers': None
    }

    def metadata(self, supports):
        _info = {}
        for key in message.FederationEntity.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info

    def get_id(self, configuration: dict):
        return ''
