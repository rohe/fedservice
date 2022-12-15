import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.key_jar import KeyJar
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.configure import Configuration
from idpyoidc.client.service import init_services
from idpyoidc.node import ClientUnit

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_SERVICES
from fedservice.entity import FederationContext

logger = logging.getLogger(__name__)


class FederationClientContext(FederationContext):
    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 priority: Optional[List[str]] = None,
                 trust_marks: Optional[List[str]] = None,
                 trusted_roots: Optional[dict] = None,
                 metadata: Optional[dict] = None,
                 ):

        if config is None:
            config = {}

        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   upstream_get=upstream_get,
                                   keyjar=keyjar,
                                   metadata=metadata,
                                   trust_marks=trust_marks,
                                   tr_priority=priority
                                   )

        self.trust_mark_issuer = None
        self.signed_trust_marks = []

        _key_jar = self.upstream_get("attribute", "keyjar")
        for iss, jwks in self.trusted_roots.items():
            _key_jar.import_jwks(jwks, iss)


class FederationClientEntity(ClientUnit):
    def __init__(
            self,
            upstream_get: Callable = None,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            metadata: Optional[dict] = None,
            trust_marks: Optional[list] = None,
            priority: Optional[list] = None
    ):
        """

        :param keyjar: A py:class:`idpyoidc.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`idpyoidc.client.service_context.ServiceContext`
            initialization
        :param httpc: A HTTP client to use
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :param httpc_params: HTTP request arguments
        :return: Client instance
        """

        ClientUnit.__init__(self, upstream_get=upstream_get, httpc=httpc,
                            keyjar=keyjar, httpc_params=httpc_params,
                            config=config)

        self._context = FederationClientContext(config=config,
                                                upstream_get=self.unit_get,
                                                metadata=metadata,
                                                trust_marks=trust_marks,
                                                priority=priority)

        _srvs = services or DEFAULT_FEDERATION_ENTITY_SERVICES

        self._service = init_services(service_definitions=_srvs, upstream_get=self.unit_get)

        self.setup_client_authn_methods(config)

    def get_attribute(self, attr, *args):
        val = getattr(self, attr)
        if val:
            return val
        else:
            return self.upstream_get('attribute', attr)

    def get_service(self, service_name, *arg):
        try:
            return self._service[service_name]
        except KeyError:
            return None

    def get_service_names(self, *args):
        return set(self._service.keys())

    def get_context(self, *args):
        return self._context

    def setup_client_authn_methods(self, config):
        if config and "client_authn_methods" in config:
            self._context.client_authn_method = client_auth_setup(
                config.get("client_authn_methods")
            )
        else:
            self._context.client_authn_method = {}

    def set_client_id(self, client_id):
        self._context.client_id = client_id
