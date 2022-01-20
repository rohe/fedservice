import logging

from oidcop.oidc import registration
from oidcmsg.oidc import RegistrationRequest

from fedservice.entity_statement.policy import diff2policy
from fedservice.entity_statement.utils import create_authority_hints

logger = logging.getLogger(__name__)


class Registration(registration.Registration):
    request_format = 'jose'
    request_placement = 'body'
    response_format = 'jose'
    endpoint_name = "federation_registration_endpoint"

    def __init__(self, server_get, **kwargs):
        registration.Registration.__init__(self, server_get, **kwargs)
        self.post_construct.append(self.create_entity_statement)

    def parse_request(self, request, auth=None, **kwargs):
        return request

    def process_request(self, request=None, **kwargs):
        """

        :param request: An entity statement in the form of a signed JT
        :param kwargs:
        :return:
        """
        _fe = self.server_get("endpoint_context").federation_entity
        _fe_cntx = _fe.context

        # Collect trust chains
        trust_chains = _fe.collect_trust_chains(request, 'openid_relying_party')

        _fe.proposed_authority_hints = create_authority_hints(_fe_cntx.authority_hints, trust_chains)

        trust_chain = _fe.pick_trust_chain(trust_chains)
        _fe.trust_chain_anchor = trust_chain.anchor
        req = RegistrationRequest(**trust_chain.metadata)
        response_info = self.non_fed_process_request(req, **kwargs)
        if "response_args" in response_info:
            payload = _fe.get_payload(request)
            _policy = diff2policy(response_info['response_args'], req)
            entity_statement = _fe_cntx.create_entity_statement(
                _fe_cntx.entity_id,
                payload['iss'],
                trust_anchor_id=trust_chain.anchor,
                metadata_policy={_fe_cntx.opponent_entity_type: _policy},
                aud=payload['iss']
            )
            response_info["response_msg"] = entity_statement
            del response_info["response_args"]

        return response_info

    def non_fed_process_request(self, req, **kwargs):
        # handle the registration request as in the non-federation case.
        return registration.Registration.process_request(self, req, authn=None, **kwargs)

    @staticmethod
    def create_entity_statement(response_args, request, endpoint_context,
                                **kwargs):
        """
        wrap the non-federation response in a federation response

        :param response_args:
        :param request:
        :param endpoint_context:
        :param kwargs:
        :return:
        """
        _fe = endpoint_context.federation_entity
        _md = {_fe.opponent_entity_type: response_args.to_dict()}
        return _fe.create_entity_statement(_fe.entity_id, sub=_fe.entity_id,
                                           metadata=_md,
                                           authority_hints=_fe.proposed_authority_hints)
