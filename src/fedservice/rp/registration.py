import logging

from cryptojwt.jws.jws import factory
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.oidc import RegistrationResponse
from oidcrp.exception import ResponseError
from oidcrp.oidc import registration

from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.collect import unverified_entity_statement
from fedservice.entity_statement.policy import apply_policy
from fedservice.entity_statement.policy import combine_policy
from fedservice.entity_statement.verify import eval_policy_chain

logger = logging.getLogger(__name__)


class Registration(registration.Registration):
    msg_type = RegistrationRequest
    response_cls = RegistrationResponse
    endpoint_name = 'federation_registration_endpoint'
    request_body_type = 'jose'
    response_body_type = 'jose'

    def __init__(self, client_get, conf=None, client_authn_factory=None, **kwargs):
        registration.Registration.__init__(self, client_get, conf=conf,
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

        _fe = self.client_get("service_context").federation_entity
        _fe_ctx = _fe.context
        _md = {_fe_ctx.entity_type: request_args.to_dict()}
        _md.update(_fe.federation_endpoint_metadata())
        return _fe_ctx.create_entity_statement(
            iss=_fe_ctx.entity_id, sub=_fe_ctx.entity_id, metadata=_md, key_jar=_fe_ctx.keyjar,
            authority_hints=_fe_ctx.proposed_authority_hints)

    def parse_response(self, info, sformat="", state="", **kwargs):
        resp = self.parse_federation_registration_response(info, **kwargs)

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def _get_trust_anchor_id(self, entity_statement):
        return entity_statement.get('trust_anchor_id')

        # _metadata = entity_statement.get('metadata')
        # if not _metadata:
        #     return None
        #
        # _fed_entity = _metadata.get('federation_entity')
        # if not _fed_entity:
        #     return None
        #
        # _trust_anchor_id = _fed_entity.get('trust_anchor_id')
        # return _trust_anchor_id

    def get_trust_anchor_id(self, entity_statement):
        _fe_context = self.client_get("service_context").federation_entity.get_context()
        if len(_fe_context.op_statements) == 1:
            _id = _fe_context.op_statements[0].anchor
            _tai = self._get_trust_anchor_id(entity_statement)
            if _tai and _tai != _id:
                logger.warning(
                    "The trust anchor id given in the registration response does not match what "
                    "is in the discovery document")
                ValueError('Trust Anchor Id mismatch')
        else:
            _id = self._get_trust_anchor_id(entity_statement)
            if _id is None:
                raise ValueError("Don't know which trust anchor to use")
        return _id

    def parse_federation_registration_response(self, resp, **kwargs):
        """
        Receives a dynamic client registration response,

        :param resp: An entity statement instance
        :return: A set of metadata claims
        """
        _context = self.client_get("service_context")
        _fe = _context.federation_entity
        _fe_ctx = _fe.context
        # Can not collect trust chain. Have to verify the signed JWT with keys I have

        kj = _fe_ctx.keyjar
        _jwt = factory(resp)
        entity_statement = _jwt.verify_compact(resp, keys=kj.get_jwt_verify_keys(_jwt.jwt))

        _trust_anchor_id = self.get_trust_anchor_id(entity_statement)

        logger.debug("trust_anchor_id: {}".format(_trust_anchor_id))
        chosen = None
        for op_statement in _fe_ctx.op_statements:
            if op_statement.anchor == _trust_anchor_id:
                chosen = op_statement
                break

        if not chosen:
            raise ValueError('No matching federation operator')

        # based on the Federation ID, conclude which OP config to use
        op_claims = chosen.metadata
        logger.debug("OP claims: {}".format(op_claims))
        # _sc.trust_path = (chosen.anchor, _fe.op_paths[statement.anchor][0])
        _context.provider_info = ProviderConfigurationResponse(**op_claims)

        # To create RPs metadata collect the trust chains
        tree = {}
        for ah in _fe_ctx.authority_hints:
            tree[ah] = _fe.collector.collect_intermediate(_fe_ctx.entity_id, ah)

        _node = {_fe_ctx.entity_id: (resp, tree)}
        chains = branch2lists(_node)
        logger.debug("%d chains", len(chains))
        logger.debug("Evaluate policy chains")
        # Get the policies
        policy_chains_tup = [eval_policy_chain(c, _fe_ctx.keyjar, _fe_ctx.entity_type) for c in chains]
        # Weed out unusable chains
        policy_chains_tup = [pct for pct in policy_chains_tup if pct is not None]
        # Should leave me with one. The one ending in the chosen trust anchor.
        policy_chains_tup = [pct for pct in policy_chains_tup if pct[0] == _trust_anchor_id]

        if policy_chains_tup == []:
            logger.warning("No chain that ends in chosen trust anchor (%s)", _trust_anchor_id)
            raise ValueError("No trust chain that ends in chosen trust anchor (%s)",
                             _trust_anchor_id)

        _policy = combine_policy(policy_chains_tup[0][1],
                                 entity_statement['metadata_policy'][_fe_ctx.entity_type])
        logger.debug("Effective policy: {}".format(_policy))
        _req = kwargs.get("request")
        if _req is None:
            _req = kwargs.get("request_body")
        _uev = unverified_entity_statement(_req)
        logger.debug("Registration request: {}".format(_uev))
        _query = _uev["metadata"][_fe_ctx.entity_type]
        _resp = apply_policy(_query, _policy)
        _context.set("registration_response", _resp)
        return _resp

    def update_service_context(self, resp, **kwargs):
        registration.Registration.update_service_context(self, resp, **kwargs)
        _fe = self.client_get("service_context").federation_entity
        _fe.iss = resp['client_id']

    def get_response_ext(self, url, method="GET", body=None, response_body_type="",
                         headers=None, **kwargs):
        """

        :param url:
        :param method:
        :param body:
        :param response_body_type:
        :param headers:
        :param kwargs:
        :return:
        """
        _context = self.client_get("service_context")
        _collector = _context.federation_entity.collector

        httpc_args = _collector.httpc_parms.copy()
        # have I seen it before
        cert_path = _collector.get_cert_path(_context.provider_info["issuer"])
        if cert_path:
            httpc_args["verify"] = cert_path

        try:
            resp = _collector.http_cli(method, url, data=body, headers=headers, **httpc_args)
        except Exception as err:
            logger.error('Exception on request: {}'.format(err))
            raise

        if 300 <= resp.status_code < 400:
            return {'http_response': resp}

        if "keyjar" not in kwargs:
            kwargs["keyjar"] = _context.keyjar
        if not response_body_type:
            response_body_type = self.response_body_type

        if response_body_type == 'html':
            return resp.text

        if body:
            kwargs['request_body'] = body

        return self.parse_response(resp, response_body_type, **kwargs)
