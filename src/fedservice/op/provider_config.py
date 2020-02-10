import logging

from cryptojwt.jwk import pems_to_x5c
from oidcendpoint.oidc import provider_config
from oidcmsg import oidc
from oidcmsg.oidc import ProviderConfigurationResponse

logger = logging.getLogger(__name__)


class ProviderConfiguration(provider_config.ProviderConfiguration):
    request_cls = oidc.Message
    response_cls = ProviderConfigurationResponse
    request_format = 'jws'
    response_format = 'jws'
    endpoint_name = 'discovery'

    def __init__(self, endpoint_context, **kwargs):
        provider_config.ProviderConfiguration.__init__(self, endpoint_context,
                                                       **kwargs)
        self.post_construct.append(self.create_entity_statement)

    def process_request(self, request=None, **kwargs):
        return {'response_args': self.endpoint_context.provider_info.copy()}

    def create_entity_statement(self, request_args, request=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param request:
        :param kwargs:
        :return:
        """

        _fe = self.endpoint_context.federation_entity
        _md = {_fe.entity_type: request_args.to_dict()}
        if _fe.collector.use_ssc:
            with open(_fe.collector.web_cert_path,'r') as fp:
                pem_cert = fp.read()
            x5c = pems_to_x5c([pem_cert])
            return _fe.create_entity_statement(_fe.entity_id, sub=_fe.entity_id, metadata=_md,
                                               x5c=x5c)
        else:
            return _fe.create_entity_statement(_fe.entity_id, sub=_fe.entity_id, metadata=_md)
