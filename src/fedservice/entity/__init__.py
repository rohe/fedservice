import json
import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.utils import importer
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.util import instantiate

from fedservice import message
from fedservice.entity_statement.create import create_entity_statement

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)




class FederationContext(OidcContext):
    parameter = OidcContext.parameter.copy()
    parameter.update({
        "default_lifetime": 0,
        "authority_hints": [],
        "tr_priority": [],
        "trust_mark_issuer": None,
        "signed_trust_marks": [],
        "trust_marks": []
    })

    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 entity_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 ):
        if config is None:
            config = {}

        self.config = config
        self.entity_get = entity_get
        self.entity_id = entity_id or config.get("entity_id")

        OidcContext.__init__(self, config, keyjar, entity_id=self.entity_id)




class FederationEntity(object):
    name = "federation_entity"

    def __init__(self,
                 entity_id: str = "",
                 keyjar: KeyJar = None,
                 trusted_roots: dict = None,
                 authority_hints: list = None,
                 client: Optional[dict] = None,
                 server: Optional[dict] = None,
                 **kwargs
                 ):

        _args = {
            "entity_get": self.entity_get,
            "keyjar": keyjar
        }

        if client:
            _kwargs = client["kwargs"]
            _kwargs.update(_args)
            self.client = instantiate(client["class"], **_kwargs)
        else:
            self.client = None

        if server:
            _kwargs = server["kwargs"]
            _kwargs.update(_args)
            self.server = instantiate(server["class"], **_kwargs)
        else:
            self.server = None

        self.context = FederationContext(trusted_roots=trusted_roots,
                                         entity_id=entity_id,
                                         entity_get=self.entity_get,
                                         authority_hints=authority_hints)

    def entity_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

    def get_context(self, *arg):
        return self.context

    def get_endpoint_context(self, *arg):
        return self.context

    def federation_endpoint_metadata(self):
        _config = self.context.config
        metadata = {}
        # collect endpoints
        endpoints = {}
        for key, item in self.server.endpoint.items():
            if key in ["fetch", "list", "status", "resolve"]:
                endpoints[f"federation_{key}_endpoint"] = item.full_path
        for attr in message.FederationEntity.c_param.keys():
            if attr in _config:
                metadata[attr] = _config[attr]
            elif attr in endpoints:
                metadata[attr] = endpoints[attr]
        return {"federation_entity": metadata}

    def get_metadata(self):
        return self.federation_endpoint_metadata()

    def get_endpoints(self, *arg):
        return self.server.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.server.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_entity(self):
        return self

# class FederationEntity(object):
#     name = "federation_entity"
#
#     def __init__(self,
#                  entity_id: str = "",
#                  config: Optional[Union[dict, Configuration]] = None,
#                  httpc: Optional[Any] = None,
#                  cwd: Optional[str] = '',
#                  httpc_params: Optional[dict] = None):
#
#         if config is None:
#             config = {}
#
#
#         self.context = FederationContext(config=config, entity_id=entity_id,
#                                          entity_get=self.entity_get)
#
#         self.collector = Collector(trust_anchors=self.context.trusted_roots,
#                                    http_cli=httpc, cwd=cwd, httpc_params=httpc_params)
#
#         if config.get("entity_id") is None:
#             config['entity_id'] = entity_id
#         if 'issuer' not in config:
#             config['issuer'] = config["entity_id"]
#
#         if 'endpoint' in config:
#             self.endpoint = do_endpoints(config, self.entity_get)
#         else:
#             self.endpoint = {}
#
#         if "service" in config:
#             self.service = do_services(config, self.entity_get())
#
#     def collect_statement_chains(self, entity_id, statement):
#         return self.collector.collect_superiors(entity_id, statement)
#
#     def eval_chains(self, chains, entity_type='', apply_policies=True):
#         """
#
#         :param chains: A list of lists of signed JWT
#         :param entity_type: The leafs entity type
#         :param apply_policies: Apply metadata policies from the list on the the metadata of the
#             leaf entity
#         :return: List of TrustChain instances
#         """
#         _context = self.context
#         if not entity_type:
#             entity_type = _context.opponent_entity_type
#
#         return [eval_chain(c, _context.keyjar, entity_type, apply_policies) for c in chains]
#
#     def get_configuration_information(self, subject_id):
#         return self.collector.get_configuration_information(subject_id)
#
#     def pick_trust_chain(self, trust_chains):
#         """
#         Pick one trust chain out of the list of possible trust chains
#
#         :param trust_chains: A list of :py:class:`fedservice.entity_statement.statement.TrustChain
#             instances
#         :return: A :py:class:`fedservice.entity_statement.statement.TrustChain instance
#         """
#         if len(trust_chains) == 1:
#             # If there is only one, then use it
#             return trust_chains[0]
#         elif self.context.tr_priority:
#             # Go by priority
#             for fid in self.context.tr_priority:
#                 for trust_chain in trust_chains:
#                     if trust_chain.anchor == fid:
#                         return trust_chain
#
#         # Can only arrive here if the federations I got back and trust are not
#         # in the priority list. So, just pick one
#         return trust_chains[0]
#
#     def get_payload(self, self_signed_statement):
#         _jws = as_unicode(self_signed_statement)
#         _jwt = factory(_jws)
#         return _jwt.jwt.payload()
#
#     def collect_trust_chains(self, self_signed_statement, metadata_type):
#         """
#
#         :param self_signed_statement: A Self signed Entity Statement
#         :param metadata_type: One of the metadata types defined in the specification
#         :return:
#         """
#         payload = self.get_payload(self_signed_statement)
#
#         # collect trust chains
#         _tree = self.collect_statement_chains(payload['iss'], payload)
#         _node = {payload['iss']: (self_signed_statement, _tree)}
#         _chains = branch2lists(_node)
#         logger.debug("%s chains", len(_chains))
#
#         # verify the trust paths and apply policies
#         return [eval_chain(c, self.context.keyjar, metadata_type) for c in _chains]
#
#     def entity_get(self, what, *arg):
#         _func = getattr(self, "get_{}".format(what), None)
#         if _func:
#             return _func(*arg)
#         return None
#
#     def get_context(self, *arg):
#         return self.context
#
#     def get_endpoint_context(self, *arg):
#         return self.context
#
#     def federation_endpoint_metadata(self):
#         _config = self.context.config
#         metadata = {}
#         # collect endpoints
#         endpoints = {}
#         for key, item in self.endpoint.items():
#             if key in ["fetch", "list", "status", "evaluate"]:
#                 endpoints[f"federation_{key}_endpoint"] = item.full_path
#         for attr in message.FederationEntity.c_param.keys():
#             if attr in _config:
#                 metadata[attr] = _config[attr]
#             elif attr in endpoints:
#                 metadata[attr] = endpoints[attr]
#         return {"federation_entity": metadata}
#
#     def get_metadata(self):
#         return self.federation_endpoint_metadata()
#
#     def get_endpoints(self, *arg):
#         return self.endpoint
#
#     def get_endpoint(self, endpoint_name, *arg):
#         try:
#             return self.endpoint[endpoint_name]
#         except KeyError:
#             return None
#
#     def get_entity(self):
#         return self
#
#     def dump(self):
#         return {
#             "context": self.context.dump(),
#             "collector": self.collector.dump()
#         }
#
#     def load(self, dump):
#         self.collector.load(dump.get("collector", {}))
#         self.context.load(dump.get("context", {}))
#
#     def get_client_id(self):
#         return self.context.entity_id
#
#     def do_services(self, config):
#
#
# def create_federation_entity(entity_id, httpc=None, httpc_params=None, cwd="", **kwargs):
#     args = {"httpc_params": httpc_params}
#     _conf = {}
#
#     _key_conf = kwargs.get("keys")
#     if _key_conf:
#         kwargs["key_conf"] = _key_conf
#
#     for param in ['trusted_roots', 'authority_hints']:
#         try:
#             _conf[param] = load_json(kwargs[param])
#         except KeyError:
#             pass
#
#     for param in ['entity_type', 'priority', 'opponent_entity_type',
#                   'registration_type', 'cwd', 'endpoint']:
#         try:
#             _conf[param] = kwargs[param]
#         except KeyError:
#             pass
#
#     for _key in ['key_conf', 'db_conf', 'issuer']:
#         _value = kwargs.get(_key)
#         if _value:
#             _conf[_key] = _value
#
#     if _conf:
#         _conf['httpc_params'] = args['httpc_params']
#         args['config'] = _conf
#
#     federation_entity = FederationEntity(entity_id, httpc=httpc, cwd=cwd, **args)
#
#     add_ons = kwargs.get("add_on")
#     if add_ons:
#         for spec in add_ons.values():
#             if isinstance(spec["function"], str):
#                 _func = importer(spec["function"])
#             else:
#                 _func = spec["function"]
#             _func(federation_entity, **spec["kwargs"])
#
#     return federation_entity
