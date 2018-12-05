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

    def do_implicit_registration(self, entity_id):
        _fe = self.endpoint_context.federation_entity

        # get self-signed entity statement
        _jarr = _fe.load_entity_statements(entity_id, entity_id)

        # collect trust chains
        _node = _fe.collect_entity_statements(_jarr)

        # verify the trust paths
        paths = _fe.eval_paths(_node)

        # If there is more then one possible path I might be in problem.

        # among the possible trust paths chose one and do flattening on the
        # metadata for that
        fid, statement = _fe.pick_metadata(paths)

        # handle the registration request as in the non-federation case.
        req = RegistrationRequest(
            **statement['metadata'][_fe.opponent_entity_type])
        return self.endpoint_context.endpoint['registration'].process_request(
            self, req, authn=None)

    def process_request(self, request=None, **kwargs):
        """ The AuthorizationRequest endpoint

        :param request: The client request as a dictionary
        :return: res
        """

        _cid = request["client_id"]

        try: # If this is a registered client then this should return some info
            self.endpoint_context.cdb[_cid]
        except KeyError: # else go the federation way
            if not self.do_implicit_registration(_cid):
                return {'error': 'unauthorized_client',
                        'error_description': 'Unknown client'}

        # Now I can do normal authorization
        return authorization.Authorization.process_request(self, request,
                                                           **kwargs)
