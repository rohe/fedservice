# Server specific defaults and a basic Server class
import json
import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.utils import importer
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.server.client_authn import client_auth_setup
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.endpoint_context import EndpointContext
from idpyoidc.server.util import build_endpoints
from idpyoidc.util import instantiate

from fedservice.entity import FederationContext
from fedservice.entity_statement.create import create_entity_statement
from fedservice.node import ServerNode

logger = logging.getLogger(__name__)


def create_self_signed_trust_marks(spec, **kwargs):
    if isinstance(spec["function"], str):
        _func = importer(spec["function"])
    else:
        _func = spec["function"]

    res = []
    for id, content in spec["kwargs"].items():
        _args = kwargs.copy()
        _args.update(content)
        res.append(_func(id=id, sub=id, **_args))
    return res


class FederationServerContext(FederationContext):
    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 server_get: Callable = None,
                 metadata: Optional[dict] = None,
                 trust_marks: Optional[List[str]] = None,
                 ):
        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   superior_get=server_get,
                                   metadata=metadata
                                   )

        self.metadata = {k: v for k, v in metadata.items() if k != 'authority_hints'}

        _sstm = config.get("self_signed_trust_marks")
        _keyjar = server_get("keyjar")
        if _sstm:
            self.signed_trust_marks = create_self_signed_trust_marks(entity_id=self.entity_id,
                                                                     keyjar=_keyjar,
                                                                     spec=_sstm)

        self.trust_marks = trust_marks

    def make_configuration_statement(self):
        _metadata = self.superior_get("metadata")
        kwargs = {}
        if self.authority_hints:
            kwargs["authority_hints"] = self.authority_hints
        if self.trust_marks:
            kwargs["trust_marks"] = self.trust_marks
        if self.signed_trust_marks:
            if "trust_marks" in kwargs:
                kwargs["trust_marks"].extend(self.signed_trust_marks)
            else:
                kwargs["trust_marks"] = self.signed_trust_marks

        return self.create_entity_statement(iss=self.entity_id, sub=self.entity_id,
                                            metadata=_metadata, **kwargs)


class FederationEntityServer(ServerNode):
    parameter = {"endpoint": [Endpoint], "endpoint_context": EndpointContext}

    def __init__(
            self,
            superior_get: Callable,
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

        ServerNode.__init__(self, superior_get=superior_get, keyjar=keyjar, context=context,
                            config=self.conf)

        if not entity_id:
            entity_id = superior_get('attribute', "entity_id")

        self.endpoint_context = FederationServerContext(
            config=self.conf,
            server_get=self.server_get,
            entity_id=entity_id,
            metadata=metadata
        )

        self.endpoint = build_endpoints(endpoint, server_get=self.server_get, issuer=entity_id)

        # self.endpoint_context.do_add_on(endpoints=self.endpoint)

        self.setup_client_authn_methods()
        for endpoint_name, _ in self.endpoint.items():
            self.endpoint[endpoint_name].server_get = self.server_get

        if subordinate:
            if 'class' in subordinate:
                _kwargs = subordinate["kwargs"]
                _kwargs.update({"server_get": self.server_get})
                self.subordinate = instantiate(subordinate["class"], **_kwargs)
            else:
                self.subordinate = subordinate
        else:
            self.subordinate = {}

    def server_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self.endpoint_context

    def get_attribute(self, attr, *args):
        val = getattr(self, attr)
        if val:
            return val
        else:
            return self.superior_get('attribute', attr)

    def get_server(self, *args):
        return self

    def setup_client_authn_methods(self):
        self.endpoint_context.client_authn_method = client_auth_setup(
            self.server_get, self.conf.get("client_authn_methods")
        )
