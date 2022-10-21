import logging

from cryptojwt.jwk import pems_to_x5c
from idpyoidc.message import oidc
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.server.oidc import provider_config

logger = logging.getLogger(__name__)


class ProviderConfiguration(provider_config.ProviderConfiguration):
    request_cls = oidc.Message
    response_cls = ProviderConfigurationResponse
    request_format = 'jws'
    response_format = 'jws'

    def __init__(self, upstream_get, **kwargs):
        provider_config.ProviderConfiguration.__init__(self, upstream_get,
                                                       **kwargs)
        self.post_construct.append(self.create_entity_statement)

    def process_request(self, request=None, **kwargs):
        return {'response_args': self.upstream_get("context").provider_info.copy()}

    def create_entity_statement(self, request_args, request=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param request:
        :param kwargs:
        :return:
        """

        _fe = self.upstream_get("context").federation_entity
        _fe_ctx = _fe.get_context()
        _md = {_fe_ctx.entity_type: request_args.to_dict()}
        if _fe.collector.use_ssc:
            with open(_fe.collector.web_cert_path, 'r') as fp:
                pem_cert = fp.read()
            x5c = pems_to_x5c([pem_cert])
            return _fe_ctx.create_entity_statement(_fe_ctx.entity_id, sub=_fe_ctx.entity_id,
                                                   metadata=_md,
                                                   x5c=x5c)
        else:
            return _fe_ctx.create_entity_statement(_fe_ctx.entity_id, sub=_fe_ctx.entity_id,
                                                   metadata=_md)
