import logging
from typing import Optional
from typing import Union

from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity import get_federation_entity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature

logger = logging.getLogger(__name__)


class MetadataVerification(Endpoint):
    request_cls = oidc.Message
    response_format = "text"
    content_type = "text/html"
    name = "metadata_verification"
    endpoint_name = 'federation_metadata_verification_endpoint'

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)

    def process_request(self, request=None, **kwargs):
        _federation_entity = get_federation_entity(self)
        payload = verify_self_signed_signature(request['registration_response'])
        # Do I trust the TA the OP chose ?
        logger.debug(f"trust_anchor_id: {payload['trust_anchor_id']}")
        if payload[
            'trust_anchor_id'] not in _federation_entity.function.trust_chain_collector.trust_anchors:
            raise ValueError("Trust anchor I don't trust")

        _chains, _ = collect_trust_chains(self.upstream_get('unit'),
                                          entity_id=payload['sub'],
                                          stop_at=payload['trust_anchor_id'])
        _trust_chains = verify_trust_chains(_federation_entity, _chains,
                                            request['registration_response'])
        # should only be one chain
        if len(_trust_chains) != 1:
            raise SystemError(f"More then one chain ending in {payload['trust_anchor_id']}")
        _trust_chains[0].verified_chain[-1]['metadata'] = payload['metadata']
        _trust_chains = apply_policies(_federation_entity, _trust_chains)
        if _trust_chains[0].metadata == payload['metadata']:
            return {"response_msg": "OK"}
        else:
            return {
                "error": "invalid_request",
                "error_description": "Could not verify the metadata"
            }

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
