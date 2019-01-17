import logging
from urllib.parse import urlencode
from urllib.parse import urlparse

from oidcservice.exception import ResponseError
from oidcservice.oidc.provider_info_discovery import ProviderInfoDiscovery

from fedservice.entity_statement.construct import \
    map_configuration_to_preference
from oidcmsg.oidc import ProviderConfigurationResponse

from fedservice.entity_statement.utils import create_authority_hints
from fedservice.exception import NoTrustedClaims
from fedservice.keybundle import KeyBundle

logger = logging.getLogger(__name__)


class FedProviderInfoDiscovery(ProviderInfoDiscovery):
    response_cls = ProviderConfigurationResponse
    request_body_type = 'jose'
    response_body_type = 'jose'

    def __init__(self, service_context, state_db, conf=None,
                 client_authn_factory=None, **kwargs):
        ProviderInfoDiscovery.__init__(
            self, service_context, state_db, conf=conf,
            client_authn_factory=client_authn_factory)

    def get_request_parameters(self, method="GET", **kwargs):
        try:
            _iss = kwargs["iss"]
        except KeyError:
            _iss = self.service_context.issuer

        qpart = {'iss': _iss}

        for param in ['sub', 'aud', 'prefetch']:
            try:
                qpart[param] = kwargs[param]
            except KeyError:
                pass

        p = urlparse(_iss)
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

        possible = list(set(paths.keys()).intersection(_fe.tr_priority))
        _fe.provider_federations = possible
        _fe.op_paths = paths

        _fe.proposed_authority_hints = create_authority_hints(
            _fe.authority_hints, paths)

        if len(possible) == 1:
            claims = paths[possible[0]][0].claims()
            _sc.provider_info = self.response_cls(**claims)
            self._update_service_context(_sc.provider_info)
            _sc.behaviour = map_configuration_to_preference(
                _sc.provider_info, _sc.client_preferences)
        else:
            # Not optimal but a reasonable estimate for now
            claims = paths[possible[0]][0].claims()
            _pinfo = self.response_cls(**claims)
            _sc.behaviour = map_configuration_to_preference(
                _pinfo, _sc.client_preferences)

    def parse_response(self, info, sformat="", state="", **kwargs):
        resp = self.parse_federation_response(info, state=state)

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def parse_federation_response(self, response, **kwargs):
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

        _fe = self.service_context.federation_entity
        _node = _fe.collect_entity_statements(response)

        return _fe.eval_paths(_node)
