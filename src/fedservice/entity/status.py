import logging

from cryptojwt.jws.jws import factory
from oidcmsg import oidc
from oidcmsg.exception import MissingAttribute
from oidcmsg.exception import MissingParameter
from oidcop.endpoint import Endpoint

from fedservice.message import EntityStatement

logger = logging.getLogger(__name__)


class Status(Endpoint):
    request_cls = oidc.Message
    response_cls = EntityStatement
    response_format = 'json'
    name = "status"

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        self.metadata_api = None

    def _check(self, id, sub, iat):
        _ism = self.server_get("entity").issued
        return _ism.find(id, sub, iat)

    def _matches_issued_trust_mark(self, request):
        _id = request.get("id")
        if _id:
            return self._check(_id, sub=request.get("sub"), iat=request.get("iat", 0))
        else:
            _tm = request.get("trust_mark")
            if not _tm:
                raise MissingAttribute('Query MUST have contain id or trust_mark')

            _jws = factory(_tm)
            _keys = self.server_get("context").keyjar.get_jwt_verify_keys(_jws.jwt)
            _info = _jws.verify_compact(keys=_keys)
            return self._check(_info["id"], _info["sub"], _info["iat"])

    def process_request(self, request=None, **kwargs):
        _msg = {"active": self._matches_issued_trust_mark(request)}
        return {'response_args': _msg}


class SelfSigned(Endpoint):
    request_cls = oidc.Message
    response_cls = EntityStatement
    response_format = 'json'
    name = "status"

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        self.metadata_api = None

    def _matches_issued_trust_mark(self, request):
        id = request.get("id")
        sub = request.get("sub")
        if sub and sub != self.server_get("context").entity_id:
            return False

        mark = request.get("trust_mark")
        for _tm in self.server_get('context').signed_trust_marks:
            if mark:
                if mark == _tm:
                    return True
            elif id:
                _jwt = factory(_tm)
                _payload = _jwt.jwt.payload()
                if _payload["id"] == id:
                    return True
            else:
                raise MissingParameter("Must provide id or mark")
        return False

    def process_request(self, request=None, **kwargs):
        _msg = {"active": self._matches_issued_trust_mark(request)}
        return {'response_args': _msg}
