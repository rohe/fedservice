import logging

from oidcmsg import oidc
from oidcop.endpoint import Endpoint

from fedservice.message import EntityStatement

logger = logging.getLogger(__name__)


class Fetch(Endpoint):
    request_cls = oidc.Message
    response_cls = EntityStatement
    response_format = 'jws'
    name = "fetch"

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        self.post_construct.append(self.create_entity_statement)
        self.metadata_api = None

    def process_request(self, request=None, **kwargs):
        _metadata = self.server_get("metadata")
        return {'response_args': _metadata}

    def create_entity_statement(self, request_args, request=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param request:
        :param kwargs:
        :return:
        """

        _context = self.server_get("context")
        _md = {_context.entity_type: request_args.to_dict()}
        return _context.create_entity_statement(iss=_context.entity_id,
                                                sub=_context.entity_id,
                                                metadata=_md)
