import logging
from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from idpyoidc.client.configure import Configuration
from idpyoidc.client.service import Service
from idpyoidc.constant import JOSE_ENCODED
from idpyoidc.message import oauth2
from oidcmsg.oauth2 import ResponseMessage
import requests

from fedservice.message import EntityStatement

logger = logging.getLogger(__name__)

WELL_KNOWN_PATTERN = "{}/.well-known/openid-federation"


def construct_well_known_url(entity_id, typ):
    p = urlparse(entity_id)
    return '{}://{}/.well-known/{}'.format(p.scheme, p.netloc, typ)


def construct_tenant_well_known_url(entity_id, typ):
    p = urlparse(entity_id)
    return '{}://{}{}/.well-known/{}'.format(p.scheme, p.netloc, p.path, typ)


class EntityConfiguration(Service):
    msg_type = oauth2.Message
    response_cls = EntityStatement
    error_msg = ResponseMessage
    synchronous = True
    service_name = "entity_configuration"
    http_method = "GET"
    response_body_type = "application/entity-statement+jwt"

    def __init__(self,
                 superior_get: Callable,
                 conf:Optional[Union[dict, Configuration]] = None):
        """The service that talks to the OIDC federation well-known endpoint."""
        Service.__init__(self, superior_get, conf=conf)
        self.httpc = requests.request
        self.httpc_params = {}

    def get_request_parameters(
            self, request_args=None, method="", request_body_type="", authn_method="",
            tenant: Optional[bool] = False, **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        This is the starting point for a pipeline that will:

        - construct the request message
        - add/remove information to/from the request message in the way a
            specific client authentication method requires.
        - gather a set of HTTP headers like Content-type and Authorization.
        - serialize the request message into the necessary format (JSON,
            urlencoded, signed JWT)

        :param request_body_type: Which serialization to use for the HTTP body
        :param method: HTTP method used.
        :param authn_method: Client authentication method
        :param request_args: Message arguments
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP
            request
        """
        if not method:
            method = self.http_method

        entity_id = request_args.get('entity_id')
        if not entity_id:
            raise AttributeError("Missing entity_id")

        if tenant:
            _url = construct_tenant_well_known_url(entity_id, "openid-federation")
        else:
            _url = construct_well_known_url(entity_id, "openid-federation")

        _info = {
            "method": method,
            "url": _url
        }

        return _info
