import json
import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWT
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.util import instantiate

from fedservice.trust_mark_issuer import TrustMarkIssuer

logger = logging.getLogger(__name__)


def create_trust_mark(keyjar, entity_id, **kwargs):
    packer = JWT(key_jar=keyjar, iss=entity_id)
    return packer.pack(payload=kwargs)


class TrustMarkStatus(Endpoint):
    request_cls = oidc.Message
    response_format = "json"
    name = "status"

    def __init__(self,
                 upstream_get: Callable,
                 trust_mark_issuer: Union[TrustMarkIssuer, dict],
                 **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        if isinstance(trust_mark_issuer, dict):
            self.trust_mark_issuer = instantiate(trust_mark_issuer['class'],
                                                 upstream_get=upstream_get,
                                                 **trust_mark_issuer['kwargs'])
        else:
            trust_mark_issuer.upstream_get = upstream_get
            self.trust_mark_issuer = trust_mark_issuer

    def process_request(self,
                        request: Optional[dict] = None,
                        **kwargs) -> dict:

        if 'trust_mark' in request:
            _mark = self.trust_mark_issuer.unpack_trust_mark(request['trust_mark'])
            if self.trust_mark_issuer.find(_mark['id'], _mark['sub']):
                return {'response': json.dumps({'active': True})}
        else:
            if 'sub' in request and 'id' in request:
                if self.trust_mark_issuer.find(request['id'], request['sub']):
                    return {'response': json.dumps({'active': True})}

        return {'response_args': json.dumps({'active': False})}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
