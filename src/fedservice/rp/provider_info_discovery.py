import logging
from urllib.parse import urlencode
from urllib.parse import urlparse

from oidcmsg.oidc import ProviderConfigurationResponse
from oidcrp.exception import ResponseError
from oidcrp.oidc.provider_info_discovery import ProviderInfoDiscovery

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

    def __init__(self, client_get, conf=None, client_authn_factory=None, **kwargs):
        ProviderInfoDiscovery.__init__(
            self, client_get, conf=conf, client_authn_factory=client_authn_factory)

    def get_request_parameters(self, method="GET", **kwargs):
        try:
            _iss = kwargs["iss"]
        except KeyError:
            _iss = self.client_get("service_context").get('issuer')

        qpart = {'iss': _iss}

        for param in ['sub', 'aud', 'prefetch']:
            try:
                qpart[param] = kwargs[param]
            except KeyError:
                pass

        p = urlparse(_iss)
        _qurl = '{}://{}/.well-known/openid-federation?{}'.format(
            p.scheme, p.netloc, urlencode(qpart))

        return {'url': _qurl, 'iss': _iss}

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

        _context = self.client_get("service_context")
        _context.set('provider_info', _pi)
        _context.federation_entity.federation = trust_root_id

    def update_service_context(self, trust_chains, **kwargs):
        """
        The list of :py:class:`fedservice.entity_statement.statement.Statement` instances are
        stored in *trust_anchors*.
        If the OP and RP only has one federation in common then the choice is
        easy and the name of the federation are stored in the *federation*
        attribute while the provider info are stored in the service_context.

        :param paths: A list of Statement instances
        :param kwargs: Extra Keyword arguments
        """

        _context = self.client_get("service_context")
        _fe_context = _context.federation_entity.context

        if _fe_context.tr_priority:
            possible = []
            for ta in _fe_context.tr_priority:
                for s in trust_chains:
                    if s.anchor == ta:
                        possible.append(ta)
        else:
            possible = [s.anchor for s in trust_chains]

        _trust_anchor = possible[0]

        _fe_context.trust_anchors = possible
        _fe_context.op_statements = trust_chains

        provider_info_per_trust_anchor = {}
        for s in trust_chains:
            if s.anchor in possible:
                claims = s.metadata
                provider_info_per_trust_anchor[s.anchor] = self.response_cls(**claims)

        #  _fe_context.provider_info_per_trust_anchor = provider_info_per_trust_anchor

        _fe_context.proposed_authority_hints = create_authority_hints(
            _fe_context.authority_hints, trust_chains)

        _pi = provider_info_per_trust_anchor[_trust_anchor]
        _context.set('provider_info', _pi)
        self._update_service_context(_pi)
        _context.set('behaviour', map_configuration_to_preference(_pi, _context.client_preferences))

    def parse_response(self, info, sformat="", state="", **kwargs):
        # returns a list of TrustChain instances
        trust_chains = self.parse_federation_response(info, state=state)
        # Get rid of NULL chains (== trust chains I can't verify)
        trust_chains = [s for s in trust_chains if s is not None]

        if not trust_chains:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return trust_chains

    def parse_federation_response(self, response, **kwargs):
        """
        Takes a provider info response and parses it.
        If according to the info the OP has more then one federation
        in common with the client then the decision has to be handled higher up.
        For each Metadata statement that appears in the response, and was
        possible to parse, one
        :py:class:`fedservice.entity_statement.statement.Statement`
        instance is stored in the response by federation operator ID under the
        key 'fos'.

        :param response: A self-signed JWT containing an entity statement
        :returns: A list of lists of Statement instances. The innermost lists represents
        trust chains
        """
        entity_statement = verify_self_signed_signature(response)
        entity_id = entity_statement['iss']

        _fe = self.client_get("service_context").federation_entity
        _tree = _fe.collect_statement_chains(entity_id, entity_statement)
        _node = {entity_id: (response, _tree)}
        logger.debug("Translate tree to chains")
        _chains = branch2lists(_node)
        logger.debug("%s chains", len(_chains))
        for c in _chains:
            c.append(response)
        return [eval_chain(c, _fe.context.keyjar, 'openid_provider') for c in _chains]

    def get_response(self, *args, **kwargs):
        """

        :param args: Just ignore these
        :param kwargs:
        :return:
        """

        _fe = self.client_get("service_context").federation_entity
        self_signed_config = _fe.collector.get_configuration_information(kwargs["iss"])
        return self.parse_response(self_signed_config)
