import json
import logging
from typing import Optional
from typing import Union

from idpyoidc.message import oidc
from idpyoidc.message import Message
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity_statement.create import create_entity_statement

logger = logging.getLogger(__name__)


class TrustMarkStatus(Endpoint):
    request_cls = oidc.Message
    response_format = "json"
    name = "status"

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)

    def process_request(self, request=None, **kwargs):

        return {'response': json.dumps({'active': True})}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
