import inspect
import logging
import sys
from urllib.parse import urlencode
from urllib.parse import urlparse

from oidcmsg.exception import RegistrationError

from fedservice.entity_statement.construct import \
    map_configuration_to_preference
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.oidc import RegistrationResponse

from oidcservice.oidc import service
from oidcservice.oidc.service import ProviderInfoDiscovery
from oidcservice.oidc.service import Registration
from oidcservice.service import Service

from fedservice.exception import NoTrustedClaims
from fedservice.keybundle import KeyBundle

logger = logging.getLogger(__name__)


class FedProviderInfoDiscovery(ProviderInfoDiscovery):
    response_cls = ProviderConfigurationResponse

    def __init__(self, service_context, state_db, conf=None,
                 client_authn_factory=None, **kwargs):
        ProviderInfoDiscovery.__init__(
            self, service_context, state_db, conf=conf,
            client_authn_factory=client_authn_factory)
        self.federation_entity = self.service_context.federation_entity

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

    def update_service_context(self, paths, **kwargs):
        """
        The list of :py:class:`fedoidcmsg.operator.LessOrEqual` instances are
        stored in *provider_federations*.
        If the OP and RP only has one federation in common then the choice is
        easy and the name of the federation are stored in the *federation*
        attribute while the provider info are stored in the service_context.

        :param paths: A dictionary with trust root entity IDs as keys and
            lists of Statement instances as values
        :param kwargs:
        """

        _sc = self.service_context
        _fe = _sc.federation_entity

        possible = list(set(paths.keys()).intersection(_fe.fo_priority))
        _fe.provider_federations = possible

        if len(possible) == 1:
            claims = paths[possible[0]][0].protected_claims()
            _sc.provider_info = self.response_cls(**claims)
            self._update_service_context(_sc.provider_info)
            _sc.behaviour = map_configuration_to_preference(
                _sc.provider_info, _sc.client_preferences)
        else:
            # Not optimal but a reasonable estimate
            claims = paths[possible[0]][0].protected_claims()
            _pinfo = self.response_cls(**claims)
            _sc.behaviour = map_configuration_to_preference(
                _pinfo, _sc.client_preferences)

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

        :param response: A signed JWT containing an entity statement
        :returns: A dictionary with trust root entity IDs as keys and
            lists of Statement instances as values
        """

        _node = self.federation_entity.collect_entity_statements(response)

        return self.federation_entity.eval_paths(_node)


class FedRegistrationRequest(Registration):
    msg_type = RegistrationRequest
    response_cls = RegistrationResponse
    endpoint_name = 'registration'
    endpoint = ''

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
        _ah = dict([(k,v) for k, v in _fe.authority_hints.items() if
               k in _fe.provider_federations])

        return _fe.create_entity_statement(request_args.to_dict(), _fe.id,
            _fe.id, authority_hints=_ah)

    def post_parse_response(self, resp, **kwargs):
        """
        Receives a dynamic client registration response, verifies the
        signature and parses the compounded metadata statement.
        If only one federation are mentioned in the response then the name
        of that federation are stored in the *federation* attribute and
        the flattened response is handled in the normal pyoidc way.
        If there are more then one federation involved then the decision
        on which to use has to be made higher up, hence the list of
        :py:class:`fedoidcmsg.operator.LessOrEqual` instances are stored in the
        attribute *registration_federations*

        :param resp: A MetadataStatement instance or a dictionary
        """
        _fe = self.service_context.federation_entity

        _node = _fe.collect_entity_statements(resp)
        paths = self.service_context.federation_entity.eval_paths(_node)
        if not paths:  # No metadata statement that I can use
            raise RegistrationError('No trusted metadata')

        # response is a dictionary with the federation identifier as keys and
        # lists of statements as values

        # At this point in time I may not know within which
        # federation I'll be working.
        fid, claims = _fe.pick_metadata(paths)
        if not fid:
            _fe.registration_federations = paths
        return claims

    def update_service_context(self, resp, state='', **kwargs):
        Registration.update_service_context(self, resp, state, **kwargs)
        _fe = self.service_context.federation_entity
        _fe.iss = resp['client_id']


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
