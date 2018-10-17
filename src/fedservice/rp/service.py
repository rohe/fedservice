import inspect
import logging
import sys
from urllib.parse import urlencode
from urllib.parse import urlparse

from cryptojwt.key_jar import KeyJar
from oidcservice.oidc import service
from oidcservice.oidc.service import ProviderInfoDiscovery
from oidcservice.service import Service

from fedservice import message
from fedservice.entity_statement.collect import Collector
from fedservice.exception import NoSuitableFederation
from fedservice.exception import NoTrustedClaims
from fedservice.keybundle import KeyBundle
from fedservice.utils import eval_paths

logger = logging.getLogger(__name__)


class FedProviderInfoDiscovery(ProviderInfoDiscovery):
    response_cls = message.EntityStatement

    def __init__(self, service_context, state_db, conf=None,
                 client_authn_factory=None, **kwargs):
        ProviderInfoDiscovery.__init__(
            self, service_context, state_db, conf=conf,
            client_authn_factory=client_authn_factory)

        self.collector = Collector(trusted_roots=service_context.trusted_roots)
        self.entity_type = 'openid_provider'
        self.tr_key_jar = KeyJar()
        for iss, jwks in service_context.trusted_roots.items():
            self.tr_key_jar.import_jwks(jwks, iss)

    def get_request_parameters(self, method="GET", **kwargs):
        qpart = {'iss': kwargs["iss"]}
        for param in ['sub', 'aud', 'prefetch']:
            try:
                qpart[param] = kwargs[param]
            except KeyError:
                pass

        p = urlparse(kwargs["iss"])
        _qurl = '{}://{}/.well-known/openid-federation?{}'.format(
            p.scheme, p.netloc, urlencode(qpart))

        return {'url': _qurl}

    def store_federation_info(self, statement, trust_root_id):
        """

        :param statement: A
            :py:class:`fedservice.entity_statement.statement.Statement` instance
        """
        # Only use trusted claims
        trusted_claims = statement.protected_claims()
        if trusted_claims is None:
            raise NoTrustedClaims()
        _pi = self.response_cls(**trusted_claims)

        if 'signed_jwks_uri' in _pi:
            _kb = KeyBundle(source=_pi['signed_jwks_uri'],
                            verify_keys=statement.signing_keys,
                            verify_ssl=False)
            _kb.do_remote()
            # Replace what was there before
            self.service_context.keyjar[self.service_context.issuer] = _kb

        self.service_context.provider_info = _pi
        self.service_context.federation_entity.federation = trust_root_id

    def update_service_context(self, metadata_set, **kwargs):
        """
        The list of :py:class:`fedoidcmsg.operator.LessOrEqual` instances are
        stored in *provider_federations*.
        If the OP and RP only has one federation in common then the choice is
        easy and the name of the federation are stored in the *federation*
        attribute while the provider info are stored in the service_context.

        :param metadata_set: A dictionary with trust root entity IDs as keys and
            lists of Statement instances as values
        :param kwargs:
        """
        if len(metadata_set) == 1 and \
                len(metadata_set[list(metadata_set.keys())[0]]) == 1:
            self.service_context.provider_info = metadata_set[
                list(metadata_set.keys())[0]]
        else:
            _fe = self.service_context.federation_entity
            # Possible FO choices
            possible = set(metadata_set.keys()).intersection(_fe.fo_priority)
            if not possible:
                raise NoSuitableFederation(
                    'Available: {}'.format(metadata_set.keys()))

            # At this point in time I may not know within which
            # federation I'll be working.
            if len(possible) == 1:
                _fo = possible.pop()
                self.store_federation_info(metadata_set[_fo][0], _fo)
            else:
                # store everything I may use of what I got for later reference
                _fe.provider_federations = possible

                # Go through the priority list and grab the first one that
                # matches and store that information in *provider_info*.
                for fo in _fe.fo_priority:
                    if fo in possible:
                        self.store_federation_info(metadata_set[fo][0], fo)
                        break

        if self.service_context.provider_info:
            self._update_service_context(self.service_context.provider_info)
            self.match_preferences(self.service_context.provider_info,
                                   self.service_context.issuer)

    def post_parse_response(self, response, **kwargs):
        """
        Takes a provider info response and parses it.
        If according to the info the OP has more then one federation
        in common with the client then the decision has to be handled higher up.
        For each Metadata statement that appears in the response, and was
        possible to parse, one
        :py:class:`fedservice.entity_statement.statement.Statement`
        instance is store in the response by federation operator ID under the
        key 'fos'.

        :param response: A MetadataStatement instance
        :returns: A dictionary with trust root entity IDs as keys and
            lists of Statement instances as values
        """

        _node = self.collector.collect_entity_statements(response)

        return eval_paths(_node, self.tr_key_jar, self.entity_type)


# class FedRegistrationRequest(Registration):
#     msg_type = ClientMetadataStatement
#     response_cls = ClientMetadataStatement
#
#     def __init__(self, service_context, state_db, conf=None,
#                  client_authn_factory=None, **kwargs):
#         Registration.__init__(self, service_context, state_db, conf=conf,
#                               client_authn_factory=client_authn_factory)
#         #
#         self.post_construct.append(self.add_federation_context)
#
#     @staticmethod
#     def carry_receiver(request, **kwargs):
#         if 'receiver' in kwargs:
#             return request, {'receiver': kwargs['receiver']}
#         else:
#             return request, {}
#
#     def add_federation_context(self, request, service=None, receiver='',
#                                **kwargs):
#         _fe = self.service_context.federation_entity
#         return _fe.update_metadata_statement(request, receiver=receiver,
#                                              context='registration')
#
#     def post_parse_response(self, resp, **kwargs):
#         """
#         Receives a dynamic client registration response, verifies the
#         signature and parses the compounded metadata statement.
#         If only one federation are mentioned in the response then the name
#         of that federation are stored in the *federation* attribute and
#         the flattened response is handled in the normal pyoidc way.
#         If there are more then one federation involved then the decision
#         on which to use has to be made higher up, hence the list of
#         :py:class:`fedoidcmsg.operator.LessOrEqual` instances are stored in the
#         attribute *registration_federations*
#
#         :param resp: A MetadataStatement instance or a dictionary
#         """
#         _fe = self.service_context.federation_entity
#
#         ms_list = _fe.get_metadata_statement(
#             resp, cls=ClientMetadataStatement)
#
#         if not ms_list:  # No metadata statement that I can use
#             raise RegistrationError('No trusted metadata')
#
#         # response is a list of registration infos
#
#         # At this point in time I may not know within which
#         # federation I'll be working.
#         if len(ms_list) == 1:
#             ms = ms_list[0]
#             resp = ms.protected_claims()
#             _fe.federation = ms.fo
#         else:
#             # apply FO priority
#             _fe.registration_federations = ms_list
#         return resp
#
#     def update_service_context(self, resp, state='', **kwargs):
#         Registration.update_service_context(self, resp, state, **kwargs)
#         _fe = self.service_context.federation_entity
#         _fe.iss = resp['client_id']


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
