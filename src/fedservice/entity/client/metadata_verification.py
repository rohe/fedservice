from typing import Callable
from typing import Optional
from typing import Union

from idpyoidc.client.configure import Configuration
from idpyoidc.client.service import Service
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.message import ResolveRequest


class MetadataVerification(Service):
    """The service that talks to the OIDC federation Metadata Verification endpoint."""

    response_cls = message.ResolveResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "metadata_verification"
    http_method = "GET"

    def __init__(self,
                 upstream_get: Callable,
                 conf:Optional[Union[dict, Configuration]] = None):
        Service.__init__(self, upstream_get, conf=conf)

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
