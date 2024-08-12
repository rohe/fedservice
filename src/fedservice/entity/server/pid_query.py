import json
import logging
from typing import Optional
from typing import Union

from idpyoidc.message import Message
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity.utils import get_federation_entity
from fedservice.message import PIDQueryRequest

logger = logging.getLogger(__name__)


class PIDQuery(Endpoint):
    request_cls = PIDQueryRequest
    response_format = "json"
    content_type = 'application/json'
    name = "pid_query"
    endpoint_name = 'federation_pid_query_endpoint'

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.entity_type = kwargs.get("entity_type", "credential_issuer")
        self.credential_type = kwargs.get("credential_type", "PersonIdentificationData")
        self.trust_mark_id = kwargs.get("trust_mark_id",
                                        "http://dc4eu.example.com/PersonIdentificationData/se")
        self.trust_anchor = kwargs.get("trust_anchor", "")

    def process_request(self, request=None, **kwargs):
        if not request:
            request = {}

        _federation_entity = get_federation_entity(self)
        # _trust_anchor = request['anchor']

        _entity_type = request.get("entity_type", self.entity_type)
        servers = []

        myself = False
        if self.trust_anchor:
            ta_id = self.trust_anchor
        else:
            ta_ids = list(_federation_entity.trust_anchors.keys())
            if ta_ids == []:
                myself = True
            else:
                ta_id = ta_ids[0]

        if not myself:
            list_resp = _federation_entity.do_request('list', entity_id=ta_id)
        else:
            list_endpoint = _federation_entity.get_endpoint("list")
            _resp = list_endpoint.process_request()
            list_resp = json.loads(_resp["response_msg"])

        # print(f"Subordinates to TA: {list_resp}")
        for entity_id in list_resp:
            servers.extend(
                _federation_entity.trawl(_federation_entity.entity_id, entity_id,
                                         entity_type=_entity_type))

        _srv = {}
        credential_type = request.get("credential_type", self.credential_type)
        for eid in set(servers):
            _metadata = _federation_entity.get_verified_metadata(eid)
            # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
            for cs in _metadata['openid_credential_issuer']["credentials_supported"]:
                if credential_type in cs["credential_definition"]["type"]:
                    _srv[eid] = _metadata
                    break

        tm_id = request.get("trust_mark_id", self.trust_mark_id)
        server_to_use = []
        for eid, metadata in _srv.items():
            _trust_chains = _federation_entity.get_trust_chains(eid)
            if not _trust_chains:
                return "Couldn't collect Trust Chains", 400
            else:
                _trust_chain = _trust_chains[0]

            _ec = _trust_chain.verified_chain[-1]
            if "trust_marks" in _ec:
                for _mark in _ec["trust_marks"]:
                    _verified_trust_mark = _federation_entity.verify_trust_mark(
                        _mark, check_with_issuer=True)
                    if _verified_trust_mark.get("id") == tm_id:
                        server_to_use.append(eid)

        return {'response_args': {"servers_to_use": server_to_use}}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
