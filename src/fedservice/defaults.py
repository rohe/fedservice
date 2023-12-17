from fedservice.message import AuthorizationServerMetadata
from fedservice.message import FederationEntity
from fedservice.message import OauthClientMetadata
from fedservice.message import OAuthProtectedResourceMetadata
from fedservice.message import OIDCRPMetadata
from fedservice.message import OPMetadataMessage
from fedservice.message import TrustMarkIssuerMetadata

ENTITY_TYPE2METADATA_CLASS = {
    "openid_relying_party": OIDCRPMetadata,
    "openid_provider": OPMetadataMessage,
    "oauth_authorization_server": AuthorizationServerMetadata,
    "oauth_client": OauthClientMetadata,
    "oauth_resource": OAuthProtectedResourceMetadata,
    "federation_entity": FederationEntity,
    "trust_mark_issuer": TrustMarkIssuerMetadata
}

DEFAULT_OIDC_FED_SERVICES = {
    'discovery': {
        'class': 'fedservice.rp.provider_info_discovery.ProviderInfoDiscovery'},
    'registration': {
        'class': 'fedservice.rp.registration.Registration'},
}

SERVICES = {
    'discovery': {
        'class': 'fedservice.rp.provider_info_discovery.ProviderInfoDiscovery',
        "kwargs": {}
    },
    'registration': {
        'class': 'fedservice.rp.registration.Registration',
        "kwargs": {}
    },
    "entity_configuration": {
        "class": 'fedservice.entity.client.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    "entity_statement": {
        "class": 'fedservice.entity.client.entity_statement.EntityStatement',
        "kwargs": {}
    },
    "trust_mark_status": {
        "class": 'fedservice.entity.client.trust_mark_status.TrustMarkStatus',
        "kwargs": {}
    },
    "resolve": {
        "class": 'fedservice.entity.client.resolve.Resolve',
        "kwargs": {}
    },
    "list": {
        "class": 'fedservice.entity.client.list.List',
        "kwargs": {}
    },
    "metadata_verification": {
        "class": "fedservice.entity.client.metadata_verification.MetadataVerification",
        "kwargs": {}
    }
}


def federation_services(*api):
    return {a: SERVICES[a] for a in api}


FEDERATION_ENTITY_SERVICES = federation_services("entity_configuration", "entity_statement",
                                                 "resolve", "list")

DEFAULT_FEDERATION_ENTITY_SERVICES = FEDERATION_ENTITY_SERVICES

FEDERATION_ENDPOINTS = {
    "entity_configuration": {
        "path": ".well-known/openid-federation",
        "class": 'fedservice.entity.server.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    "fetch": {
        "path": "fetch",
        "class": 'fedservice.entity.server.fetch.Fetch',
        "kwargs": {}
    },
    "list": {
        "path": "list",
        "class": 'fedservice.entity.server.list.List',
        "kwargs": {}
    },
    "resolve": {
        "path": "resolve",
        "class": 'fedservice.entity.server.resolve.Resolve',
        "kwargs": {}
    },
    "status": {
        "path": "status",
        "class": 'fedservice.entity.server.status.TrustMarkStatus',
        "kwargs": {}
    },
    "metadata_verification": {
        "path": "verifier",
        "class": "fedservice.entity.server.metadata_verification.MetadataVerification",
        "kwargs": {}
    }
}


def federation_endpoints(*apis) -> dict:
    return {a: FEDERATION_ENDPOINTS[a] for a in apis}


INTERMEDIATE_ENDPOINTS = federation_endpoints("entity_configuration", "fetch", "list")
DEFAULT_FEDERATION_ENTITY_ENDPOINTS = INTERMEDIATE_ENDPOINTS

LEAF_ENDPOINTS = federation_endpoints("entity_configuration")

TRUST_MARK_ISSUER_ENDPOINTS = federation_endpoints("entity_configuration", "status")

WELL_KNOWN_FEDERATION_ENDPOINT = "{}/.well-known/openid-federation"

FEDERATION_ENTITY_FUNCTIONS = {
    "trust_chain_collector": {
        "class": 'fedservice.entity.function.trust_chain_collector.TrustChainCollector',
        "kwargs": {
            'trust_anchors': {},
            "allowed_delta": 600
        }
    },
    'verifier': {
        'class': 'fedservice.entity.function.verifier.TrustChainVerifier',
        'kwargs': {}
    },
    'policy': {
        'class': 'fedservice.entity.function.policy.TrustChainPolicy',
        'kwargs': {}
    },
    'trust_mark_verifier': {
        'class': 'fedservice.entity.function.trust_mark_verifier.TrustMarkVerifier',
        'kwargs': {}
    },
    'metadata_verifier': {
        'class': 'fedservice.entity.function.metadata_verifier.MetadataVerifier',
        'kwargs': {}
    }
}


def federation_functions(*apis):
    return {a: FEDERATION_ENTITY_FUNCTIONS[a] for a in apis}


DEFAULT_FEDERATION_ENTITY_FUNCTIONS = federation_functions("trust_chain_collector", "verifier",
                                                           "policy", "trust_mark_verifier")
