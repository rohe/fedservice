import logging

from oidcmsg import oidc
from oidcmsg.oidc import RegistrationRequest
from oidcop.oidc import authorization

logger = logging.getLogger(__name__)


class Authorization(authorization.Authorization):
    msg_type = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_msg = oidc.ResponseMessage

    def __init__(self, server_get, **kwargs):
        authorization.Authorization.__init__(self, server_get, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        # self.post_parse_request.append(self._post_parse_request)
        self.automatic_registration_endpoint = None

    def do_automatic_registration(self, entity_id):
        _fe = self.server_get("endpoint_context").federation_entity

        # get self-signed entity statement
        _sses = _fe.get_configuration_information(entity_id)

        # Collect all the trust chains, verify them and apply policies. return the result
        trust_chains = _fe.collect_trust_chains(_sses, "openid_relying_party")

        # pick one of the possible
        trust_chain = _fe.pick_trust_chain(trust_chains)
        _fe.trust_chain_anchor = trust_chain.anchor

        # handle the registration request as in the non-federation case.
        req = RegistrationRequest(**trust_chain.metadata)
        req['client_id'] = entity_id
        new_id = self.automatic_registration_endpoint.kwargs.get("new_id", False)
        response_info = self.automatic_registration_endpoint.non_fed_process_request(req,
                                                                                     new_id=new_id)
        try:
            return response_info["response_args"]["client_id"]
        except KeyError:
            return None

    def client_authentication(self, request, auth=None, **kwargs):

        _cid = request["client_id"]
        _context = self.server_get("endpoint_context")
        # If this is a registered client then this should return some info
        client_info = _context.cdb.get(_cid)
        if client_info is None:
            if self.automatic_registration_endpoint:  # try the federation way
                registered_client_id = self.do_automatic_registration(_cid)
                if registered_client_id is None:
                    return {
                        'error': 'unauthorized_client',
                        'error_description': 'Unknown client'
                    }
                else:
                    logger.debug('Automatic registration done')
                    if registered_client_id != _cid:
                        request["client_id"] = registered_client_id
                        kwargs["also_known_as"] = {_cid: registered_client_id}
                        client_info = _context.cdb[registered_client_id]
                        _context.cdb[_cid] = client_info
                        client_info['entity_id'] = _cid
                        # _context.cdb[registered_client_id] = client_info
            else:
                return {
                    'error': 'unauthorized_client',
                    'error_description': 'Unknown client'
                }

        # then do client authentication
        return authorization.Authorization.client_authentication(
            self, request, auth, **kwargs)

    def extra_response_args(self, aresp):
        aresp['trust_anchor_id'] = self.server_get(
            "endpoint_context").federation_entity.trust_chain_anchor
        return aresp
