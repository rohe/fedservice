import logging
from typing import Callable
from typing import Optional

from cryptojwt import as_unicode
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from idpyoidc.util import instantiate
from requests import request

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import verify_trust_chains

__author__ = 'Roland Hedberg'

from fedservice.entity.context import FederationContext
from idpyoidc.node import Unit

logger = logging.getLogger(__name__)


class FederationEntity(Unit):
    name = "federation_entity"

    def __init__(self,
                 upstream_get: Optional[Callable] = None,
                 entity_id: str = "",
                 keyjar: Optional[KeyJar] = None,
                 key_conf: Optional[dict] = None,
                 client: Optional[dict] = None,
                 server: Optional[dict] = None,
                 function: Optional[dict] = None,
                 httpc: Optional[object] = None,
                 httpc_params: Optional[dict] = None,
                 preference: Optional[dict] = None,
                 authority_hints: Optional[list] = None,
                 **kwargs
                 ):

        if upstream_get is None and httpc is None:
            httpc = request

        if not keyjar and not key_conf:
            keyjar = False

        self.entity_id = entity_id
        Unit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                      httpc_params=httpc_params, key_conf=key_conf, issuer_id=entity_id)

        _args = {
            "upstream_get": self.unit_get,
            "httpc": self.httpc,
            "httpc_params": self.httpc_params,
            "entity_id": entity_id
        }

        self.client = self.server = self.function = None
        for key, val in [('client', client), ('server', server), ('function', function)]:
            if val:
                _kwargs = val["kwargs"].copy()
                _kwargs.update(_args)
                setattr(self, key, instantiate(val["class"], **_kwargs))

        self.context = FederationContext(entity_id=entity_id, upstream_get=self.unit_get,
                                         authority_hints=authority_hints, keyjar=self.keyjar,
                                         preference=preference)

        self.trust_chain = {}

    def get_context(self, *arg):
        return self.context

    def get_federation_entity(self):
        return self

    def get_entity_type(self, entity_type):
        if entity_type == "federation_entity":
            return self
        else:
            return None

    def get_attribute(self, attr, *args):
        try:
            val = getattr(self, attr)
        except AttributeError:
            if self.upstream_get:
                return self.upstream_get('attribute', attr)
            else:
                return None
        else:
            if not val:
                if self.upstream_get:
                    return self.upstream_get('attribute', attr)
                else:
                    return None
            else:
                return val

    def get_function(self, function_name, *args):
        if self.function:
            try:
                return getattr(self.function, function_name)
            except AttributeError:
                return None

    def get_metadata(self):
        metadata = self.get_context().claims.prefer
        # collect endpoints
        metadata.update(self.get_endpoint_claims())
        return {"federation_entity": metadata}

    def get_preferences(self):
        preference = self.get_context().claims.prefer
        # collect endpoints
        preference.update(self.get_endpoint_claims())
        return {"federation_entity": preference}

    def get_endpoints(self, *arg):
        if self.server:
            return self.server.endpoint
        else:
            return None

    def get_endpoint(self, endpoint_name, *arg):
        if self.server is None:
            return None

        try:
            return self.server.get_endpoint(endpoint_name)
        except KeyError:
            return None

    def get_service(self, service_name, *arg):
        try:
            return self.client.get_service(service_name)
        except KeyError:
            return None

    def get_authority_hints(self, *args):
        return self.context.authority_hints

    def get_context_attribute(self, attr, *args):
        _val = getattr(self.context, attr, None)
        if not _val and self.upstream_get:
            return self.upstream_get('context_attribute', attr)
        else:
            return _val

    def pick_trust_chain(self, trust_chains):
        """
        Pick one trust chain out of the list of possible trust chains

        :param trust_chains: A list of :py:class:`fedservice.entity_statement.statement.TrustChain
            instances
        :return: A :py:class:`fedservice.entity_statement.statement.TrustChain instance
        """
        if len(trust_chains) == 1:
            # If there is only one, then use it
            return trust_chains[0]
        elif self.context.tr_priority:
            # Go by priority
            for fid in self.context.tr_priority:
                for trust_chain in trust_chains:
                    if trust_chain.anchor == fid:
                        return trust_chain

        # Can only arrive here if the federations I got back and trust are not
        # in the priority list. So, just pick one
        return trust_chains[0]

    def get_payload(self, self_signed_statement):
        _jws = as_unicode(self_signed_statement)
        _jwt = factory(_jws)
        return _jwt.jwt.payload()

    def supported(self):
        _supports = self.context.supports()
        if self.server:
            _supports.update(self.server.context.supports())
        return _supports

    def get_endpoint_claims(self):
        _info = {}
        for endp in self.get_endpoints().values():
            if endp.endpoint_name:
                _info[endp.endpoint_name] = endp.full_path
        return _info

    def get_trust_chain(self, entity_id):
        _trust_chain = self.trust_chain.get(entity_id)
        if _trust_chain is None:
            _trust_chains = get_verified_trust_chains(self, entity_id)
            if _trust_chains:
                self.trust_chain[entity_id] = _trust_chains
                _trust_chain = _trust_chains[0]

        if _trust_chain:
            return _trust_chain.chain
        else:
            return None

    def get_verified_metadata(self, entity_id):
        _trust_chain = self.trust_chain.get(entity_id)
        if _trust_chain is None:
            _trust_chains = get_verified_trust_chains(self, entity_id)
            if _trust_chains:
                self.trust_chain[entity_id] = _trust_chains
                _trust_chain = _trust_chains[0]

        if _trust_chain:
            return _trust_chain.metadata
        else:
            return None

    def do_request(
            self,
            request_type: str,
            response_body_type: Optional[str] = "",
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            **kwargs):
        return self.client.do_request(request_type=request_type,
                                      response_body_type=response_body_type,
                                      request_args=request_args, behaviour_args=behaviour_args,
                                      **kwargs)

    def trawl(self, superior, subordinate, entity_type):
        if subordinate in self.function.trust_chain_collector.config_cache:
            _ec = self.function.trust_chain_collector.config_cache[subordinate]
        else:
            _es = self.client.do_request("entity_statement", issuer=superior, subject=subordinate)

            # add subjects key/-s to keyjar
            self.get_federation_entity().keyjar.import_jwks(_es["jwks"], _es["sub"])

            # Fetch Entity Configuration
            _ec = self.client.do_request("entity_configuration", entity_id=subordinate)

        if "federation_list_endpoint" not in _ec["metadata"]["federation_entity"]:
            return []

        # One step down the tree
        # All subordinates that are of a specific entity_type
        _issuers = self.client.do_request("list",
                                          entity_id=subordinate,
                                          entity_type=entity_type)
        if _issuers is None:
            _issuers = []

        # All subordinates that are intermediates
        _intermediates = self.client.do_request("list",
                                                entity_id=subordinate,
                                                intermediate=True)

        # For all intermediates go further down the tree
        if _intermediates:
            for entity_id in _intermediates:
                _ids = self.trawl(subordinate, entity_id, entity_type)
                if _ids:
                    _issuers.extend(_ids)

        return _issuers
