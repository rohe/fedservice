import json
import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from idpyoidc.message import oidc
from idpyoidc.message import Message
from idpyoidc.server.endpoint import Endpoint

from fedservice.message import TrustMark

logger = logging.getLogger(__name__)


class TrustMarkStatus(Endpoint):
    request_cls = oidc.Message
    response_format = "json"
    name = "status"

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)

    def process_request(self, request=None, **kwargs):
        _tmi = self.upstream_get('server').upstream_get('unit')

        if 'trust_mark' in request:
            _mark = self.unpack_trust_mark(request['trust_mark'])
            if _tmi.issued.find(_mark['id'], _mark['sub']):
                return {'response': json.dumps({'active': True})}
        else:
            if 'sub' in request and 'id' in request:
                if _tmi.issued.find(request['id'], request['sub']):
                    return {'response': json.dumps({'active': True})}

        return {'response': json.dumps({'active': False})}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args

    def unpack_trust_mark(self, token, entity_id: Optional[str] = ""):
        keyjar = self.upstream_get('attribute', 'keyjar')
        _jwt = JWT(key_jar=keyjar, msg_cls=TrustMark, allowed_sign_algs=["RS256"])
        _tm = _jwt.unpack(token)

        if entity_id:
            _tm.verify(entity_id=entity_id)
        else:
            _tm.verify()

        return _tm
