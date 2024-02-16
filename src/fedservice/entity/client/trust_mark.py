from typing import Callable
from typing import Optional
from typing import Union

from idpyoidc.client.configure import Configuration
from idpyoidc.exception import MissingAttribute
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.message import TrustMarkRequest


class TrustMark(FederationService):
    """The service that talks to the OIDC federation Status endpoint."""

    msg_type = oauth2.Message
    response_cls = message.Message
    error_msg = ResponseMessage
    synchronous = True
    service_name = "trust_mark"
    http_method = "GET"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def get_headers_args(self):
        # audience = _server_endpoint.full_path,
        # algorithm = "ES256",

        return {"client_id": self.upstream_get("context").entity_id}

    def construct_request(
            self,
            request_args: Optional[dict] = None,
            **kwargs
    ) -> Message:
        """
        Builds the request message and constructs the HTTP headers.

        :param request_args: Message arguments
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP request
        """

        if "trust_mark_id" not in request_args:
            raise MissingAttribute("Need a trust mark id")

        return TrustMarkRequest(**request_args)
