import logging

from oidcendpoint.oidc import authorization
from oidcmsg import oidc
from oidcmsg.oidc import RegistrationRequest

logger = logging.getLogger(__name__)


class Authorization(authorization.Authorization):
    msg_type = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_msg = oidc.ResponseMessage

    def __init__(self, endpoint_context, **kwargs):
        authorization.Authorization.__init__(self, endpoint_context, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        # self.post_parse_request.append(self._post_parse_request)
        self.automatic_registration_endpoint = None

    def do_automatic_registration(self, entity_id):
        _fe = self.endpoint_context.federation_entity

        # get self-signed entity statement
        _sses = _fe.get_configuration_information(entity_id)

        # Collect all the trust chains, verify them and apply policies. return the result
        statements = _fe.collect_metadata_statements(_sses, "openid_relying_party")

        # pick one of the possible
        statement = _fe.pick_metadata(statements)

        # handle the registration request as in the non-federation case.
        req = RegistrationRequest(**statement.metadata)
        req['client_id'] = entity_id
        new_id = self.automatic_registration_endpoint.kwargs.get("new_id", False)
        response_info = self.automatic_registration_endpoint.process_request(req, new_id=new_id)
        try:
            return response_info["response_args"]["client_id"]
        except KeyError:
            return None

    def client_authentication(self, request, auth=None, **kwargs):

        _cid = request["client_id"]

        try:  # If this is a registered client then this should return some info
            self.endpoint_context.cdb[_cid]
        except KeyError:  # else go the federation way
            registered_client_id = self.do_automatic_registration(_cid)
            if registered_client_id is None:
                return {
                    'error': 'unauthorized_client',
                    'error_description': 'Unknown client'
                }
            else:
                request["client_id"] = registered_client_id
                kwargs["also_known_as"] = {_cid: registered_client_id}

        # then do client authentication
        return authorization.Authorization.client_authentication(
            self, request, auth, **kwargs)
