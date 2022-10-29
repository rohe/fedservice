import logging

from idpyoidc.message import oidc
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.node import topmost_unit
from idpyoidc.server.oidc import provider_config

logger = logging.getLogger(__name__)


class ProviderConfiguration(provider_config.ProviderConfiguration):
    request_cls = oidc.Message
    response_cls = ProviderConfigurationResponse
    request_format = 'jws'
    response_format = 'jws'
    response_content_type = 'entity-statement+jwt'

    def __init__(self, upstream_get, **kwargs):
        provider_config.ProviderConfiguration.__init__(self, upstream_get,
                                                       **kwargs)
        self.post_construct.append(self.create_entity_statement)

    def process_request(self, request=None, **kwargs):
        return {'response_args': self.upstream_get("context").provider_info.copy()}

    def create_entity_statement(self, response_args, request=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param request:
        :param kwargs:
        :return:
        """

        _fe = topmost_unit(self)['federation_entity']
        _entity_type = self.upstream_get('unit').name
        _md = {_entity_type: response_args.to_dict()}
        # if getattr(_fe.function.trust_chain_collector, 'use_ssc'):
        #     with open(_fe.function.trust_chain_collector.web_cert_path, 'r') as fp:
        #         pem_cert = fp.read()
        #     x5c = pems_to_x5c([pem_cert])
        #     return _fe_ctx.create_entity_statement(_fe.entity_id, sub=_fe.entity_id,
        #                                            metadata=_md,
        #                                            x5c=x5c)
        # else:
        _fe = topmost_unit(self)['federation_entity']

        return _fe.get_context().create_entity_statement(
            iss=_fe.entity_id,
            sub=_fe.entity_id,
            authority_hints=_fe.get_authority_hints(),
            metadata=_md)
