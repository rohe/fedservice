import logging

from oidcop.endpoint import Endpoint
from oidcmsg import oidc

from fedservice.message import EntityStatement

logger = logging.getLogger(__name__)


class FederationAPI(Endpoint):
    request_cls = oidc.Message
    response_cls = EntityStatement
    response_format = 'jws'

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        self.post_construct.append(self.create_entity_statement)
        self.metadata_api = None

    def process_request(self, request=None, **kwargs):
        return {'response_args': self.server_get("endpoint_context").provider_info.copy()}

    def create_entity_statement(self, request_args, request=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param request:
        :param kwargs:
        :return:
        """

        _fe = self.server_get("endpoint_context").federation_entity
        _md = {_fe.entity_type: request_args.to_dict()}
        return _fe.create_entity_statement(_fe.entity_id, sub=_fe.entity_id, metadata=_md)
