import logging

from cryptojwt.jws.jws import factory

from fedservice.entity_statement.collect import unverified_entity_statement
from fedservice.entity_statement.policy import combine_policy

from fedservice.entity_statement.policy import apply_policy
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.oidc import RegistrationResponse
from oidcservice.exception import ResponseError
from oidcservice.oidc.registration import Registration

from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.verify import eval_policy_chain

logger = logging.getLogger(__name__)


class FedRegistration(Registration):
    msg_type = RegistrationRequest
    response_cls = RegistrationResponse
    endpoint_name = 'registration_endpoint'
    endpoint = 'registration'
    request_body_type = 'jose'
    response_body_type = 'jose'

    def __init__(self, service_context, state_db, conf=None,
                 client_authn_factory=None, **kwargs):
        Registration.__init__(self, service_context, state_db, conf=conf,
                              client_authn_factory=client_authn_factory)
        #
        self.post_construct.append(self.create_entity_statement)

    @staticmethod
    def carry_receiver(request, **kwargs):
        if 'receiver' in kwargs:
            return request, {'receiver': kwargs['receiver']}
        else:
            return request, {}

    def create_entity_statement(self, request_args, service=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param service:
        :param kwargs:
        :return:
        """

        _fe = self.service_context.federation_entity
        _md = {_fe.entity_type: request_args.to_dict()}
        return _fe.create_entity_statement(
            iss=_fe.entity_id, sub=_fe.entity_id, metadata=_md, key_jar=_fe.key_jar,
            authority_hints=_fe.proposed_authority_hints)

    def parse_response(self, info, sformat="", state="", **kwargs):
        resp = self.parse_federation_registration_response(info, **kwargs)

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def parse_federation_registration_response(self, resp, **kwargs):
        """
        Receives a dynamic client registration response,

        :param resp: An entity statement instance
        :return: A set of metadata claims
        """
        _sc = self.service_context
        _fe = _sc.federation_entity

        # Can not collect trust chain. Have to verify the signed JWT with keys I have

        kj = self.service_context.federation_entity.key_jar
        _jwt = factory(resp)
        entity_statement = _jwt.verify_compact(resp, keys=kj.get_jwt_verify_keys(_jwt.jwt))

        _fo = entity_statement['metadata']["federation_entity"]["trust_anchor_id"]
        chosen = None
        for op_statement in _fe.op_statements:
            if op_statement.fo == _fo:
                chosen = op_statement
                break

        if not chosen:
            raise ValueError('No matching federation operator')

        # based on the Federation ID, conclude which OP config to use
        op_claims = chosen.metadata
        # _sc.trust_path = (chosen.fo, _fe.op_paths[statement.fo][0])
        _sc.provider_info = self.response_cls(**op_claims)

        # To create RPs metadata collect the trust chains
        tree = {}
        for ah in _fe.authority_hints:
            tree[ah] = _fe.collector.collect_intermediate(_fe.entity_id, ah)

        _node = {_fe.entity_id: (resp, tree)}
        chains = branch2lists(_node)

        # Get the policies
        policy_chains_tup = [eval_policy_chain(c, _fe.key_jar, _fe.entity_type) for c in chains]
        _policy = combine_policy(policy_chains_tup[0][1],
                                 entity_statement['metadata_policy'][_fe.entity_type])
        print("Combined policy: {}".format(_policy))
        _query = unverified_entity_statement(kwargs["request_body"])["metadata"][_fe.entity_type]
        _sc.registration_response = apply_policy(_query, _policy)
        return _sc.registration_response

    def update_service_context(self, resp, **kwargs):
        Registration.update_service_context(self, resp, **kwargs)
        _fe = self.service_context.federation_entity
        _fe.iss = resp['client_id']
