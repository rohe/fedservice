import logging

from cryptojwt.jws.jws import factory
from idpyoidc.client.exception import ResponseError
from idpyoidc.client.oidc import registration
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse

from fedservice.entity import get_federation_entity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains

logger = logging.getLogger(__name__)


class Registration(registration.Registration):
    msg_type = RegistrationRequest
    response_cls = RegistrationResponse
    endpoint_name = 'federation_registration_endpoint'
    request_body_type = 'jose'
    response_body_type = 'jose'
    name = 'registration'

    def __init__(self, upstream_get, conf=None, client_authn_factory=None, **kwargs):
        registration.Registration.__init__(self, upstream_get, conf=conf)
        #
        self.post_construct.append(self.create_entity_statement)

    # def get_provider_info_attributes(self):
    #     _pia = construct_provider_info(self.provider_info_attributes, **self.kwargs)
    #     if self.endpoint_name:
    #         _pia[self.endpoint_name] = self.full_path
    #     return _pia

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

        _federation_entity = get_federation_entity(self)
        # _md = {_federation_context.entity_type: request_args.to_dict()}
        _combo = _federation_entity.upstream_get('unit')
        _md = _combo.get_metadata()
        _keyjar = _federation_entity.get_attribute("keyjar")
        _authority_hints = _federation_entity.get_authority_hints()
        _context = _federation_entity.get_context()
        _entity_id = _federation_entity.upstream_get('attribute', 'entity_id')
        _jws = _context.create_entity_statement(
            iss=_entity_id,
            sub=_entity_id,
            metadata=_md,
            key_jar=_keyjar,
            authority_hints=_authority_hints,
            trust_marks=_context.trust_marks)
        # store for later reference
        _federation_entity.entity_configuration = _jws
        return _jws

    def parse_response(self, info, sformat="", state="", **kwargs):
        resp = self.parse_federation_registration_response(info, **kwargs)

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def _get_trust_anchor_id(self, entity_statement):
        return entity_statement.get('trust_anchor_id')

    def parse_federation_registration_response(self, resp, **kwargs):
        """
        Receives a dynamic client registration response,

        :param resp: An entity statement as a signed JWT
        :return: A set of metadata claims
        """
        _federation_entity = get_federation_entity(self)
        # Need the federation keys
        keyjar = _federation_entity.upstream_get('attribute', 'keyjar')

        # should have the necessary keys
        _jwt = factory(resp)
        entity_statement = _jwt.verify_compact(resp, keys=keyjar.get_jwt_verify_keys(_jwt.jwt))

        _trust_anchor_id = entity_statement['trust_anchor_id']
        logger.debug(f"trust_anchor_id: {_trust_anchor_id}")

        if _trust_anchor_id not in _federation_entity.function.trust_chain_collector.trust_anchors:
            raise ValueError("Trust anchor I don't trust")

        try:
            chosen = _federation_entity.context.trust_chains[_trust_anchor_id]
        except KeyError:
            raise KeyError(f"No valid Trust Chain Anchor: {_trust_anchor_id}")

        # based on the Federation ID, conclude which OP config to use and store the
        # provider configuration in its proper place.
        op_claims = chosen.metadata['openid_provider']
        logger.debug(f"OP claims: {op_claims}")
        # _sc.trust_path = (chosen.anchor, _fe.op_paths[statement.anchor][0])
        _context = self.upstream_get('context')
        _context.provider_info = ProviderConfigurationResponse(**op_claims)

        _chains, _ = collect_trust_chains(self.upstream_get('unit'),
                                          entity_id=entity_statement['sub'],
                                          signed_entity_configuration=resp,
                                          stop_at=_trust_anchor_id,
                                          authority_hints=_federation_entity.get_authority_hints())

        _trust_chains = verify_trust_chains(_federation_entity, _chains, resp,
                                            _federation_entity.entity_configuration)
        _trust_chains = apply_policies(_federation_entity, _trust_chains)
        _resp = _trust_chains[0].metadata['openid_relying_party']
        _context.registration_response = _resp
        return _resp

    def update_service_context(self, resp, **kwargs):
        registration.Registration.update_service_context(self, resp, **kwargs)
        _fe = self.upstream_get("context").federation_entity
        _fe.iss = resp['client_id']

