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
    'discovery': {
        'class': 'fedservice.rp.provider_info_discovery.ProviderInfoDiscovery'},
    'registration': {
        'class': 'fedservice.rp.registration.Registration'},
}

FEDERATION_ENTITY_SERVICES = {
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
    }
}

DEFAULT_FEDERATION_ENTITY_SERVICES = FEDERATION_ENTITY_SERVICES

DEFAULT_FEDERATION_ENTITY_ENDPOINTS = {
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
    }
}

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
    }
}

LEAF_ENDPOINT = {
    "entity_configuration": {
        "path": ".well-known/openid-federation",
        "class": 'fedservice.entity.server.entity_configuration.EntityConfiguration',
        "kwargs": {}
    }
}
