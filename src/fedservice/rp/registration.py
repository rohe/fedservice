import logging

from cryptojwt.jws.jws import factory
from idpyoidc.client.exception import ResponseError
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.client.oidc import registration

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

    def __init__(self, upstream_get, conf=None, client_authn_factory=None, **kwargs):
        registration.Registration.__init__(self, upstream_get, conf=conf)
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

        _federation_entity = self.upstream_get('Unit').upstream_get('Unit')["federation_entity"]
        _federation_context = _federation_entity.context
        # _md = {_federation_context.entity_type: request_args.to_dict()}
        _combo = _federation_entity.upstream_get('Unit')
        _md = _combo.get_metadata()
        _keyjar = _federation_entity.get_attribute("keyjar")
        _authority_hints = _federation_entity.server.endpoint_context.authority_hints
        _jws = _federation_context.create_entity_statement(
            iss=_federation_context.entity_id, sub=_federation_context.entity_id,
            metadata=_md, key_jar=_keyjar,
            authority_hints=_authority_hints,
            trust_marks=_federation_context.trust_marks)
        _federation_context.entity_configuration = _jws
        return _jws

    def parse_response(self, info, sformat="", state="", **kwargs):
        resp = self.parse_federation_registration_response(info, **kwargs)

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def _get_trust_anchor_id(self, entity_statement):
        return entity_statement.get('trust_anchor_id')

    def get_trust_anchor_id(self, entity_statement):
        _fe_context = self.upstream_get("context").federation_entity.get_context()
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

        :param resp: An entity statement as a signed JWT
        :return: A set of metadata claims
        """
        _federation_entity = self.upstream_get('Unit').upstream_get('Unit')['federation_entity']
        # Need the federation keys
        keyjar = _federation_entity.upstream_get('attribute', 'keyjar')

        # should have the necessary keys
        _jwt = factory(resp)
        entity_statement = _jwt.verify_compact(resp, keys=keyjar.get_jwt_verify_keys(_jwt.jwt))

        _trust_anchor_id = entity_statement['trust_anchor_id']
        logger.debug("trust_anchor_id: {}".format(_trust_anchor_id))

        if _trust_anchor_id not in _federation_entity.function.trust_chain_collector.trust_anchors:
            raise ValueError("Trust anchor I don't trust")

        try:
            chosen = _federation_entity.context.trust_chains[_trust_anchor_id]
        except KeyError:
            raise KeyError(f"No valid Trust Chain Anchor: {_trust_anchor_id}")

        # based on the Federation ID, conclude which OP config to use and store the
        # provider configuration in its proper place.
        op_claims = chosen.metadata['openid_provider']
        logger.debug("OP claims: {}".format(op_claims))
        # _sc.trust_path = (chosen.anchor, _fe.op_paths[statement.anchor][0])
        _context = self.upstream_get('context')
        _context.provider_info = ProviderConfigurationResponse(**op_claims)

        _authority_hints = _federation_entity.server.endpoint_context.authority_hints
        _chains, _ = collect_trust_chains(self.upstream_get('Unit'),
                                          entity_id=entity_statement['sub'],
                                          signed_entity_configuration=resp,
                                          stop_at=_trust_anchor_id,
                                          authority_hints=_authority_hints)

        _trust_chains = verify_trust_chains(_federation_entity, _chains, resp,
                                            _federation_entity.context.entity_configuration)
        _trust_chains = apply_policies(_federation_entity, _trust_chains)
        _resp = _trust_chains[0].metadata['openid_relying_party']
        _context.registration_response = _resp
        return _resp

    def update_service_context(self, resp, **kwargs):
        registration.Registration.update_service_context(self, resp, **kwargs)
        _fe = self.upstream_get("context").federation_entity
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
        _context = self.upstream_get("context")
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
