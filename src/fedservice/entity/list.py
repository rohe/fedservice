import logging

from oidcop.endpoint import Endpoint
from oidcmsg import oidc

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
        self.server_get("context").subordinates = kwargs["subordinates"]

    def process_request(self, request=None, **kwargs):
        _db = self.server_get("context").subordinates
        return {'response_args': list(_db.keys())}

