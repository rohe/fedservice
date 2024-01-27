import logging
from urllib.parse import urlencode
from urllib.parse import urlparse

from idpyoidc.client.exception import ResponseError
from idpyoidc.client.oauth2 import server_metadata
from idpyoidc.message.oauth2 import ASConfigurationResponse
from idpyoidc.node import topmost_unit

from fedservice.entity.function import apply_policies
from fedservice.entity.function import tree2chains
from fedservice.entity.function import verify_self_signed_signature
from fedservice.entity.function import verify_trust_chains
from fedservice.entity_statement.statement import chains2dict

logger = logging.getLogger(__name__)


def pick_preferred_trust_anchor(trust_chains, federation_context):
    if federation_context.tr_priority:
        possible = []
        for ta in federation_context.tr_priority:
            for s in trust_chains:
                if s.anchor == ta:
                    possible.append(ta)
    else:
        possible = [s.anchor for s in trust_chains]

    return possible[0]


class ServerMetadata(server_metadata.ServerMetadata):
    response_cls = ASConfigurationResponse
    request_body_type = 'jose'
    response_body_type = 'jose'
    name = "server_metadata"

    def __init__(self, upstream_get, conf=None, **kwargs):
        server_metadata.ServerMetadata.__init__(self, upstream_get, conf=conf)

    def get_request_parameters(self, method="GET", **kwargs):
        try:
            _iss = kwargs["iss"]
        except KeyError:
            _iss = self.upstream_get("context").get('issuer')

        qpart = {'iss': _iss}

        for param in ['sub', 'aud', 'prefetch']:
            try:
                qpart[param] = kwargs[param]
            except KeyError:
                pass

        p = urlparse(_iss)
        _qurl = '{}://{}/.well-known/openid-federation?{}'.format(
            p.scheme, p.netloc, urlencode(qpart))

        return {'method': method, 'url': _qurl, 'iss': _iss}

    def update_service_context(self, trust_chains, **kwargs):
        """
        The list of :py:class:`fedservice.entity_statement.statement.Statement` instances are
        stored in *trust_anchors*.
        If the OP and RP only has one federation in common then the choice is
        easy and the name of the federation are stored in the *federation*
        attribute while the provider info are stored in the service_context.

        :param trust_chains: A list of TrustChain instances
        :param kwargs: Extra Keyword arguments
        """

        # First deal with federation relates things
        _federation_entity = self.upstream_get("entity").upstream_get('unit')['federation_entity']
        _federation_context = _federation_entity.get_context()

        # If two chains lead to the same trust anchor only one remains after this
        _federation_context.trust_chains = chains2dict(trust_chains)

        provider_info_per_trust_anchor = {}
        for entity_id, trust_chain in _federation_context.trust_chains.items():
            claims = trust_chain.metadata['openid_relaying_party']
            provider_info_per_trust_anchor[entity_id] = self.response_cls(**claims)

        # _federation_context.proposed_authority_hints = create_authority_hints(trust_chains)
        #
        # if not _federation_context.proposed_authority_hints:
        #     raise AttributeError("No possible authority hints")

        _anchor = pick_preferred_trust_anchor(trust_chains, _federation_context)

        # And now for core OIDC related
        _pi = provider_info_per_trust_anchor[_anchor]

        _context = self.upstream_get("context")
        _context.set('provider_info', _pi)
        self._update_service_context(_pi)
        # _client = self.upstream_get("entity")
        # _metadata = _client.get_metadata()
        # _metadata.update(_federation_entity.get_metadata())
        # _context.set('behaviour',
        #              map_configuration_to_preference(_pi, _metadata['openid_relying_party']))

    def parse_response(self, info, sformat="", state="", **kwargs):
        # returns a list of TrustChain instances
        trust_chains = self.parse_federation_response(info, state=state)
        # Get rid of NULL chains (== trust chains I can't verify, don't trust)
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
        entity_config = verify_self_signed_signature(response)
        entity_id = entity_config['iss']

        combo = topmost_unit(self)
        _collector = combo['federation_entity'].function.trust_chain_collector
        _collector.config_cache[entity_id] = entity_config

        _tree = _collector.collect_tree(entity_id, entity_config)

        logger.debug("Translate tree to chains")
        _chains = tree2chains(_tree)
        logger.debug("%s chains", len(_chains))

        _trust_chains = verify_trust_chains(combo['federation_entity'], _chains, response)
        return apply_policies(combo['federation_entity'], _trust_chains)

    def get_response(self, *args, **kwargs):
        """

        :param args: Just ignore these
        :param kwargs:
        :return:
        """

        _fe = self.upstream_get("context").federation_entity
        self_signed_config = _fe.collector.get_configuration_information(kwargs["iss"])
        return self.parse_response(self_signed_config)
