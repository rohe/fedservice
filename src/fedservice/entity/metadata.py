from idpyoidc import metadata
from idpyoidc.client.metadata import oauth2 as OAuth2ClientMetadata
from idpyoidc.client.metadata import oidc as OIDCClientMetadata
from idpyoidc.metadata import Metadata as MetadataBase
from idpyoidc.server.metadata import oauth2 as OAUTH2Metadata
from idpyoidc.server.metadata import oidc as OIDCMetadata

from fedservice import message as fedservice_message

class OPMetadata(OIDCMetadata.Metadata):
    _supports = OIDCMetadata.Metadata._supports.copy()
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
        for key in fedservice_message.OPMetadataMessage.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info


class ASWorkEnvironment(OAUTH2Metadata.Metadata):
    _supports = OAUTH2Metadata.Metadata._supports.copy()
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

    def verify_rules(self):
        pass

    def provider_info(self, supports):
        _info = {}
        for key in fedservice_message.AuthorizationServerMetadata.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info


class RPMetadata(OIDCClientMetadata.Metadata):
    _supports = OIDCClientMetadata.Metadata._supports.copy()

    register2preferred = OIDCClientMetadata.REGISTER2PREFERRED
    registration_response = fedservice_message.OIDCRPRegistrationResponse
    registration_request = fedservice_message.OIDCRPMetadata


class ClientMetadata(OAuth2ClientMetadata.Metadata):
    _supports = OAuth2ClientMetadata.Metadata._supports.copy()

    register2preferred = OAuth2ClientMetadata.REGISTER2PREFERRED
    registration_response = fedservice_message.OauthClientInformationResponse
    registration_request = fedservice_message.OauthClientMetadata


class FederationEntityMetadata(MetadataBase):
    _supports = {
        'organization_name': None,
        'contacts': None,
        'policy_uri': None,
        'homepage_uri': None
    }

    def metadata(self, supports):
        _info = {}
        for key in fedservice_message.FederationEntity.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info

    def get_id(self, configuration: dict):
        return ''
