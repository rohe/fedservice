import logging

from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.server.oidc import registration

from fedservice.entity.utils import get_federation_entity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature

logger = logging.getLogger(__name__)


class Registration(registration.Registration):
    request_format = 'jose'
    request_placement = 'body'
    response_format = 'jose'
    endpoint_name = "federation_registration_endpoint"
    _status = {
        "client_registration_types_supported": ["automatic", "explicit"]
    }

    def __init__(self, upstream_get, **kwargs):
        registration.Registration.__init__(self, upstream_get, **kwargs)
        self.post_construct.append(self.create_entity_statement)

    def parse_request(self, request, auth=None, **kwargs):
        return request

    def process_request(self, request=None, **kwargs):
        """

        :param request: An entity statement in the form of a signed JT
        :param kwargs:
        :return:
        """
        payload = verify_self_signed_signature(request)
        opponent_entity_type = set(payload['metadata'].keys()).difference({'federation_entity',
                                                                           'trust_mark_issuer'}).pop()
        _federation_entity = get_federation_entity(self)

        # Collect trust chains
        _chains, _ = collect_trust_chains(self.upstream_get('unit'),
                                          entity_id=payload['sub'],
                                          signed_entity_configuration=request)
        _trust_chains = verify_trust_chains(_federation_entity, _chains, request)
        _trust_chains = apply_policies(_federation_entity, _trust_chains)
        trust_chain = _federation_entity.pick_trust_chain(_trust_chains)
        _federation_entity.trust_chain_anchor = trust_chain.anchor
        # Perform non-federation registration
        req = RegistrationRequest(**trust_chain.metadata[opponent_entity_type])
        response_info = self.non_fed_process_request(req, **kwargs)
        if "response_args" in response_info:
            _context = _federation_entity.context
            _policy_metadata = req.to_dict()
            _policy_metadata.update(response_info['response_args'])
            # Should I filter out stuff I have no reason to change ?
            _policy_metadata = {k: v for k, v in _policy_metadata.items() if k not in [
                'application_type',
                'jwks',
                'redirect_uris']}
            entity_statement = _context.create_entity_statement(
                _federation_entity.upstream_get('attribute', 'entity_id'),
                payload['iss'],
                trust_anchor_id=trust_chain.anchor,
                metadata={opponent_entity_type: _policy_metadata},
                aud=payload['iss'],
            )
            response_info["response_msg"] = entity_statement
            del response_info["response_args"]

        return response_info

    def non_fed_process_request(self, req, **kwargs):
        # handle the registration request as in the non-federation case.
        return registration.Registration.process_request(self, req, authn=None, **kwargs)

    @staticmethod
    def create_entity_statement(response_args, request, context,
                                **kwargs):
        """
        wrap the non-federation response in a federation response

        :param response_args:
        :param request:
        :param context:
        :param kwargs:
        :return:
        """
        _fe = context.federation_entity
        _md = {_fe.opponent_entity_type: response_args.to_dict()}
        return _fe.create_entity_statement(_fe.entity_id, sub=_fe.entity_id,
                                           metadata=_md,
                                           authority_hints=_fe.get_authority_hints(),
                                           trust_marks=_fe.context.trust_marks)
