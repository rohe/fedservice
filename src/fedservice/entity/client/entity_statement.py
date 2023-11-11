from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlencode

from idpyoidc.client.configure import Configuration
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.entity.utils import get_federation_entity


def construct_entity_configuration_query(api_endpoint, issuer="", subject=""):
    if issuer:
        if subject:
            query = urlencode({"iss": issuer, "sub": subject})
        else:
            query = urlencode({"iss": issuer})

        return f"{api_endpoint}?{query}"
    else:
        return f"{api_endpoint}"


class EntityStatement(FederationService):
    """The service that talks to the OIDC federation Fetch endpoint."""

    msg_type = oauth2.Message
    response_cls = message.EntityStatement
    error_msg = ResponseMessage
    synchronous = True
    service_name = "entity_statement"
    http_method = "GET"
    endpoint_name = "federation_fetch_endpoint"
    response_body_type = "jose"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            method: Optional[str] = "",
            request_body_type: Optional[str] = "",
            authn_method: Optional[str] = "",
            fetch_endpoint: Optional[str] = "",
            issuer: Optional[str] = "",
            subject: Optional[str] = "",
            **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        :param method: HTTP method used.
        :param authn_method: Client authentication method
        :param request_args: Message arguments
        :param request_body_type:
        :param fetch_endpoint:
        :param issuer:
        :param subject:
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP request
        """
        if not method:
            method = self.http_method

        if not fetch_endpoint:
            root = get_federation_entity(self)
            _collector = root.function.trust_chain_collector
            _ec = _collector.config_cache[issuer]
            fetch_endpoint = _ec["metadata"]["federation_entity"][self.endpoint_name]
            if not fetch_endpoint:
                raise AttributeError("Missing endpoint")

        msg = Message()
        if issuer:
            msg['iss'] = issuer
            if subject:
                msg['sub'] = subject

        return {"url": msg.request(fetch_endpoint), 'method': method}
