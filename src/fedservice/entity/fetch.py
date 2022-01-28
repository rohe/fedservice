import logging

from oidcmsg import oidc
from oidcop.endpoint import Endpoint

from fedservice.exception import FedServiceError
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
        _context = self.server_get("context")
        _issuer = request.get("iss")
        if not _issuer:
            raise FedServiceError("Issuer mandatory")
        if _issuer != _context.entity_id:
            raise FedServiceError("Wrong issuer")

        _sub = request.get("sub")
        if not _sub or _sub == _context.entity_id:
            _response = {"metadata": self.server_get("metadata")}
            _response["jwks"] = _context.keyjar.export_jwks()
            if _context.authority_hints:
                _response["authority_hints"] = _context.authority_hints
        else:
            _response = _context.subordinates[_sub]
            _response["authority_hints"] = [_issuer]

        return {'response_args': _response}

    def create_entity_statement(self, request_args, request=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param request:
        :param kwargs:
        :return:
        """

        _context = self.server_get("context")
        _payload = request_args.to_dict()
        _sub = request.get("sub")
        if not _sub:
            _sub = _context.entity_id

        return _context.create_entity_statement(iss=_context.entity_id, sub=_sub, **_payload)
