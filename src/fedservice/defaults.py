from fedservice.message import AuthorizationServerMetadata
from fedservice.message import FederationEntity
from fedservice.message import OAuthProtectedResourceMetadata
from fedservice.message import OIDCRPMetadata
from fedservice.message import OPMetadata
from fedservice.message import OauthClientMetadata
from fedservice.message import TrustMarkIssuerMetadata

ENTITY_TYPE2METADATA_CLASS = {
    "openid_relying_party": OIDCRPMetadata,
    "openid_provider": OPMetadata,
    "oauth_authorization_server": AuthorizationServerMetadata,
    "oauth_client": OauthClientMetadata,
    "oauth_resource": OAuthProtectedResourceMetadata,
    "federation_entity": FederationEntity,
    "trust_mark_issuer": TrustMarkIssuerMetadata
}

DEFAULT_OIDC_FED_SERVICES = {
    'provider_info': {
        'class':
            'fedservice.entity.client.provider_info_discovery.ProviderInfoDiscovery'},
    'registration': {
        'class': 'fedservice.entity.client.registration.Registration'},
}
