import logging

from cryptojwt.jws.jws import factory
from fedservice.entity_statement.verify import eval_chain

from fedservice.entity_statement.collect import branch2lists

from fedservice.entity_statement.utils import create_authority_hints
from oidcendpoint.oidc import registration
from oidcmsg.oidc import RegistrationRequest

logger = logging.getLogger(__name__)


class Registration(registration.Registration):
    request_format = 'jose'
    request_placement = 'body'
    response_format = 'jose'

    def __init__(self, endpoint_context, **kwargs):
        registration.Registration.__init__(self, endpoint_context, **kwargs)
        self.post_construct.append(self.create_entity_statement)

    def parse_request(self, request, auth=None, **kwargs):
        return request

    def process_request(self, request=None, **kwargs):
        _fe = self.endpoint_context.federation_entity

        _jwt = factory(request)
        payload = _jwt.jwt.payload()

        # collect trust chains
        _tree = _fe.collect_statement_chains(payload['iss'], request)
        _chains = branch2lists(_tree)
        # verify the trust paths
        statements = [eval_chain(c, _fe.key_jar, 'openid_client') for c in _chains]

        _fe.proposed_authority_hints = create_authority_hints(
            _fe.authority_hints, statements)

        statement = _fe.pick_metadata(statements)

        # handle the registration request as in the non-federation case.
        req = RegistrationRequest(**statement.metadata)
        return registration.Registration.process_request(
            self, req, authn=None, **kwargs)

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
            metadata=_md, authority_hints=_fe.proposed_authority_hints)
