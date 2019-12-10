import logging
from urllib.parse import urlencode
from urllib.parse import urlparse

from cryptojwt.jws.jws import factory
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcservice.exception import ResponseError
from oidcservice.oidc.provider_info_discovery import ProviderInfoDiscovery

from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.entity_statement.construct import map_configuration_to_preference
from fedservice.entity_statement.utils import create_authority_hints
from fedservice.entity_statement.verify import eval_chain
from fedservice.exception import NoTrustedClaims

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
        trusted_claims = statement.metadata
        if trusted_claims is None:
            raise NoTrustedClaims()
        _pi = self.response_cls(**trusted_claims)

        # Temporarily (?) taken out
        # if 'signed_jwks_uri' in _pi:
        #     _kb = KeyBundle(source=_pi['signed_jwks_uri'],
        #                     verify_keys=statement.signing_keys,
        #                     verify_ssl=False)
        #     _kb.do_remote()
        #     # Replace what was there before
        #     self.service_context.keyjar[self.service_context.issuer] = _kb

        self.service_context.provider_info = _pi
        self.service_context.federation_entity.federation = trust_root_id

    def update_service_context(self, statements, **kwargs):
        """
        The list of :py:class:`fedservice.entity_statement.statement.Statement` instances are
        stored in *provider_federations*.
        If the OP and RP only has one federation in common then the choice is
        easy and the name of the federation are stored in the *federation*
        attribute while the provider info are stored in the service_context.

        :param paths: A list of Statement instances
        :param kwargs: Extra Keyword arguments
        """

        _sc = self.service_context
        _fe = _sc.federation_entity

        possible = list(set([s.fo for s in statements]).intersection(_fe.tr_priority))

        _fe.provider_federations = possible
        _fe.op_statements = statements

        _fe.proposed_authority_hints = create_authority_hints(
            _fe.authority_hints, statements)

        if len(possible) == 1:
            for s in statements:
                if s.fo == possible[0]:
                    claims = s.metadata
                    _sc.provider_info = self.response_cls(**claims)
                    self._update_service_context(_sc.provider_info)
                    _sc.behaviour = map_configuration_to_preference(
                        _sc.provider_info, _sc.client_preferences)
        else:
            # Not optimal but a reasonable estimate for now
            claims = statements[0].metadata
            _pinfo = self.response_cls(**claims)
            _sc.behaviour = map_configuration_to_preference(
                _pinfo, _sc.client_preferences)

    def parse_response(self, info, sformat="", state="", **kwargs):
        # returns a list of Statement instances
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

        :param response: A self-signed JWT containing an entity statement
        :returns: A list of lists of Statement instances. The innermost lists represents
        trust chains
        """

        _jwt = factory(response)
        entity_statement = _jwt.jwt.payload()
        entity_id = entity_statement['iss']

        _fe = self.service_context.federation_entity

        metadata = verify_self_signed_signature(response)
        _tree = _fe.collect_statement_chains(entity_id, metadata)
        _node = {entity_id: (response, _tree)}
        _chains = branch2lists(_node)
        for c in _chains:
            c.append(response)
        return [eval_chain(c, _fe.key_jar, 'openid_provider') for c in _chains]
