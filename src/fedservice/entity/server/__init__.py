# Server specific defaults and a basic Server class
import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.context import OidcContext
from idpyoidc.server.client_authn import client_auth_setup
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.endpoint_context import EndpointContext
from idpyoidc.server.util import build_endpoints
from idpyoidc.util import instantiate

from fedservice.server import ServerUnit

logger = logging.getLogger(__name__)


class FederationEntityServer(ServerUnit):
    parameter = {"endpoint": [Endpoint], "endpoint_context": EndpointContext}

    def __init__(
            self,
            upstream_get: Callable,
            config: Optional[Union[dict, OPConfiguration, ASConfiguration]] = None,
            keyjar: Optional[KeyJar] = None,
            context: Optional[OidcContext] = None,
            entity_id: Optional[str] = "",
            endpoint: Optional[dict] = None,
            metadata: Optional[dict] = None,
            subordinate: Optional[dict] = None,
            httpc: Optional[object] = None,
            httpc_params: Optional[dict] = None,
    ):
        if config is None:
            config = {}
        self.conf = config

        ServerUnit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, context=context,
                            config=self.conf, metadata=metadata)

        if not entity_id:
            entity_id = upstream_get('attribute', "entity_id")

        self.endpoint = build_endpoints(endpoint, upstream_get=self.unit_get, issuer=entity_id)

        # self.endpoint_context.do_add_on(endpoints=self.endpoint)

        self.setup_client_authn_methods()
        for endpoint_name, _ in self.endpoint.items():
            self.endpoint[endpoint_name].unit_get = self.unit_get

        if subordinate:
            if 'class' in subordinate:
                _kwargs = subordinate["kwargs"]
                _kwargs.update({"server_get": self.unit_get})
                self.subordinate = instantiate(subordinate["class"], **_kwargs)
            else:
                self.subordinate = subordinate
        else:
            self.subordinate = {}

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self._service_context

    def get_attribute(self, attr, *args):
        val = getattr(self, attr)
        if val:
            return val
        else:
            return self.upstream_get('attribute', attr)

    def get_server(self, *args):
        return self

    def setup_client_authn_methods(self):
        self._service_context.client_authn_method = client_auth_setup(
            self.unit_get, self.conf.get("client_authn_methods")
        )
