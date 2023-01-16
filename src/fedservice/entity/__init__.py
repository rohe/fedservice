import logging
from typing import Callable
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from idpyoidc.util import instantiate
from requests import request

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
                 metadata: Optional[dict] = None,
                 authority_hints: Optional[list] = None,
                 **kwargs
                 ):

        if upstream_get is None and httpc is None:
            httpc = request

        self.entity_id = entity_id
        Unit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                      httpc_params=httpc_params, key_conf=key_conf, issuer_id=entity_id)

        _args = {
            "upstream_get": self.unit_get,
            "httpc": self.httpc,
            "httpc_params": self.httpc_params,
        }

        self.client = self.server = self.function = None
        for key, val in [('client', client), ('server', server), ('function', function)]:
            if val:
                _kwargs = val["kwargs"].copy()
                _kwargs.update(_args)
                setattr(self, key, instantiate(val["class"], **_kwargs))

        self.context = FederationContext(entity_id=entity_id, upstream_get=self.unit_get,
                                         authority_hints=authority_hints, keyjar=self.keyjar,
                                         metadata=metadata)


    def get_context(self, *arg):
        return self.context

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
            return getattr(self.function, function_name)

    def get_metadata(self):
        metadata = self.get_context().metadata.prefer
        # collect endpoints
        endpoints = {}
        for key, item in self.server.endpoint.items():
            if key in ["fetch", "list", "resolve", 'status']:
                metadata[f"federation_{key}_endpoint"] = item.full_path
        return {"federation_entity": metadata}

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


def get_federation_entity(unit):
    # Look both upstream and downstream if necessary
    if isinstance(unit, FederationEntity):
        return unit
    elif unit.upstream_get:
        return get_federation_entity(unit.upstream_get('unit'))
    else:
        return unit['federation_entity']
