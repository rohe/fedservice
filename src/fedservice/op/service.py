import inspect
import logging
import sys

from oidcendpoint.oidc import provider_config
from oidcendpoint.oidc import registration
from oidcmsg import oidc
from oidcmsg.oidc import ProviderConfigurationResponse
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
        return _fe.create_entity_statement(request_args.to_dict(), _fe.id,
                                           _fe.id)


class Registration(registration.Registration):
    def process_request(self, request=None, **kwargs):
        _fe = self.endpoint_context.federation_entity
        _node = _fe.collect_entity_statements(request)
        fid, claims = _fe.pick_metadata(_fe.eval_paths(_node))
        request = registration.Registration.process_request(self, claims,
                                                            authn=None,
                                                            **kwargs)
        result = {}
        return {'response_args': result}


#             else:
#                 return {'error': 'access_denied',
#                         'error_description': 'Anonymous client registration '
#                                              'not allowed'}
#
#         try:
#             request.verify()
#         except Exception as err:
#             logger.exception(err)
#             return ResponseMessage(error='Invalid request')
#
#         logger.info(
#             "registration_request:{}".format(sanitize(request.to_dict())))
#
#         _fe = self.endpoint_context.federation_entity
#
#         les = _fe.get_metadata_statement(request, context='registration')
#
#         if les:
#             ms = _fe.pick_by_priority(les)
#             _fe.federation = ms.fo
#         else:  # Nothing I can use
#             return ResponseMessage(
#                 error='invalid_request',
#                 error_description='No signed metadata statement I could use')
#
#         _pc = ClientMetadataStatement(**ms.protected_claims())
#
#         if _pc:
#             resp = self.client_registration_setup(_pc)
#         else:
#             resp = self.client_registration_setup(
#                 ms.unprotected_and_protected_claims())
#
#         result = ClientMetadataStatement(**resp.to_dict())
#
#         if 'signed_jwks_uri' in _pc:
#             _kb = KeyBundle(source=_pc['signed_jwks_uri'],
#                             verify_keys=ms.signing_keys,
#                             verify_ssl=False)
#             _kb.do_remote()
#             replace_jwks_key_bundle(self.endpoint_context.keyjar,
#                                     result['client_id'], _kb)
#             result['signed_jwks_uri'] = _pc['signed_jwks_uri']
#
#         result = _fe.update_metadata_statement(result, context='response')


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
