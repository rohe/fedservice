from typing import Callable
from typing import Optional
from typing import Union

from idpyoidc.client.configure import Configuration
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.message import ResolveRequest


class Resolve(FederationService):
    """The service that talks to the OIDC federation List endpoint."""

    response_cls = message.ResolveResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "resolve"
    http_method = "GET"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            authn_method: Optional[str] = "",
            endpoint: Optional[str] = "",
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
            self.upstream_get('unit')
            raise AttributeError("Missing endpoint")

        _req = ResolveRequest(**request_args)
        _req.verify()

        return {"url": _req.request(endpoint), 'method': self.http_method}
