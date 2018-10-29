import inspect
import logging
import sys

from oidcendpoint.client_authn import UnknownOrNoAuthnMethod

from fedservice.entity_statement.utils import create_authority_hints
from oidcendpoint.oidc import provider_config
from oidcendpoint.oidc import registration
from oidcmsg import oidc
from oidcmsg.oidc import ProviderConfigurationResponse, RegistrationRequest
from oidcservice.oidc import service
from oidcservice.service import Service

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
        return _fe.create_entity_statement(_md, _fe.entity_id, _fe.entity_id)


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
        # collect trust chains
        _node = _fe.collect_entity_statements(request)

        # verify the trust paths
        paths = _fe.eval_paths(_node, flatten=False)

        _fe.proposed_authority_hints = create_authority_hints(
            _fe.authority_hints, paths)

        fid, statement = _fe.pick_metadata(paths)
        # handle the registration request as in the non-federation case.
        req = RegistrationRequest(
            **statement['metadata'][_fe.opponent_entity_type])
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
        return _fe.create_entity_statement(
            _md, _fe.entity_id, _fe.entity_id,
            authority_hints=_fe.proposed_authority_hints)


def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Service):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass

    # If not here look at oidcservice.oidc.service
    return service.factory(req_name, **kwargs)
