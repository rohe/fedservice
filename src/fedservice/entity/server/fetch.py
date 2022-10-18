import logging

from fedservice.entity_statement.create import create_entity_statement
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice.exception import FedServiceError
from fedservice.message import EntityStatement

logger = logging.getLogger(__name__)


class Fetch(Endpoint):
    request_cls = oidc.Message
    response_cls = EntityStatement
    response_format = 'jws'
    name = "fetch"

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get=upstream_get, **kwargs)
        self.post_construct.append(self.create_entity_statement)
        self.metadata_api = None

    def process_request(self, request=None, **kwargs):
        _context = self.upstream_get("context")
        _issuer = request.get("iss")
        if not _issuer:
            _issuer = _context.entity_id

        _sub = request.get("sub")
        _keyjar =  self.upstream_get('attribute', 'keyjar')
        if not _sub or _sub == _context.entity_id:
            _server = self.upstream_get("server")
            _entity = _server.upstream_get('Unit')
            _metadata = _entity.get_metadata()
            _es = create_entity_statement(iss=_entity.context.entity_id,
                                          sub=_entity.context.entity_id,
                                          key_jar=_keyjar,
                                          metadata=_metadata,
                                          authority_hints=_server.endpoint_context.authority_hints)
        else:
            _response = self.upstream_get('unit').subordinate[_sub]
            _response["authority_hints"] = [_issuer]

            _es = create_entity_statement(iss=_issuer,
                                          sub=_sub,
                                          key_jar=_keyjar,
                                          **_response
                                          )
        return {"response": _es}

    def create_entity_statement(self, request_args, request=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param request:
        :param kwargs:
        :return:
        """

        _context = self.upstream_get("context")
        _payload = request_args.to_dict()
        _sub = request.get("sub")
        if not _sub:
            _sub = _context.entity_id

        return _context.create_entity_statement(iss=_context.entity_id, sub=_sub, **_payload)
