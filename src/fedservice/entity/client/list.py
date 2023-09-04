from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlencode

from fedservice.entity import FederationEntity
from idpyoidc.client.configure import Configuration
from idpyoidc.client.service import Service
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.node import topmost_unit

from fedservice.entity import federation_entity
from fedservice.message import ListResponse


class List(Service):
    """The service that talks to the OIDC federation List endpoint."""

    response_cls = ListResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "list"
    http_method = "GET"
    endpoint_name = "federation_list_endpoint"

    def __init__(self,
                 upstream_get: Callable,
                 conf:Optional[Union[dict, Configuration]] = None):
        Service.__init__(self, upstream_get, conf=conf)

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            authn_method: Optional[str] = "",
            endpoint: Optional[str] = "",
            entity_id: Optional[str] = "",
            **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        :param request_args: Message arguments
        :param authn_method: Client authentication method
        :param endpoint:
        :param kwargs: extra keyword arguments
        :return: List of entity IDs
        """
        if not endpoint:
            root = federation_entity(self)
            _collector = root.function.trust_chain_collector
            _ec = _collector.config_cache[entity_id]
            endpoint = _ec["metadata"]["federation_entity"][self.endpoint_name]
            if not endpoint:
                raise AttributeError("Missing endpoint")

        qpart = {}
        for arg in ["entity_type", "trust_marked", "trust_mark_id", "intermediate"]:
            val = kwargs.get(arg)
            if val:
                qpart[arg] = val

        if qpart:
            return {"url": f"{endpoint}?{urlencode(qpart)}", 'method': self.http_method}
        else:
            return {"url": f"{endpoint}", 'method': self.http_method}
