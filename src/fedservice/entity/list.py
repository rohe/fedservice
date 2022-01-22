import logging
from typing import Optional
from typing import Union

from oidcmsg.message import Message
from oidcop.endpoint import Endpoint
from oidcmsg import oidc
from oidcop.endpoint_context import init_service

logger = logging.getLogger(__name__)


class List(Endpoint):
    request_cls = oidc.Message
    # response_cls = EntityIDList
    response_format = 'json'
    name = "list"

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        # self.post_construct.append(self.create_entity_statement)
        self.metadata_api = None
        _subs = kwargs["subordinates"]

        if "class" in _subs and "kwargs" in _subs:
            self.server_get("context").subordinates = init_service(_subs)
        else:
            self.server_get("context").subordinates = _subs

    def process_request(self, request=None, **kwargs):
        _db = self.server_get("context").subordinates
        return {'response_args': list(_db.keys())}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
        ) -> dict:
        return response_args

