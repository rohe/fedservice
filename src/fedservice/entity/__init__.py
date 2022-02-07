import json
import logging
from typing import Any
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from oidcmsg.configure import Configuration
from oidcmsg.context import OidcContext
from oidcop.util import build_endpoints
from oidcop.util import importer
from requests import request

from fedservice import message
from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.create import create_entity_statement
from fedservice.entity_statement.verify import eval_chain
from fedservice.utils import load_json

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


def do_endpoints(conf, server_get):
    endpoints = build_endpoints(conf["endpoint"], server_get=server_get, issuer=conf["entity_id"])

    _cap = conf.get("capabilities", {})

    for endpoint, endpoint_instance in endpoints.items():
        if endpoint_instance.endpoint_info:
            for key, val in endpoint_instance.endpoint_info.items():
                if key not in _cap:
                    _cap[key] = val

    return endpoints


def create_self_signed_trust_marks(spec, **kwargs):
    if isinstance(spec["function"], str):
        _func = importer(spec["function"])
    else:
        _func = spec["function"]

    res = []
    for id, content in spec["kwargs"].items():
        _args = kwargs.copy()
        _args.update(content)
        res.append(_func(id=id, sub=id, **_args))
    return res


class FederationContext(OidcContext):
    parameter = OidcContext.parameter.copy()
    parameter.update({
        "entity_type": "",
        "opponent_entity_type": "",
        "registration_type": "",
        "default_lifetime": 0,
        "trusted_roots": {},
        "collector": Collector,
        "authority_hints": [],
        "tr_priority": [],
        "trust_mark_issuer": None,
        "signed_trust_marks": [],
        "trust_marks": []
    })

    def __init__(self,
                 config: Union[dict, Configuration],
                 entity_id: str = "",
                 server_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 authority_hints: Optional[Union[List[str], str]] = None,
                 default_lifetime: Optional[int] = 86400,
                 priority: Optional[List[str]] = None,
                 entity_type: Optional[str] = '',
                 opponent_entity_type: Optional[str] = '',
                 registration_type: Optional[str] = '',
                 trust_marks: Optional[List[str]] = None
                 ):

        self.config = config
        self.server_get = server_get
        self.entity_id = entity_id or config.get("entity_id")

        OidcContext.__init__(self, config, keyjar, entity_id=self.entity_id)

        self.entity_type = entity_type or config.get("entity_type")
        self.opponent_entity_type = opponent_entity_type or config.get("opponent_entity_type", "")
        self.registration_type = registration_type or config.get("registration_type", "")
        self.default_lifetime = default_lifetime or config.get("default_lifetime", 0)
        self.trust_mark_issuer = None
        self.signed_trust_marks = []
        self.trust_marks = trust_marks or config.get("trust_marks", [])

        _trusted_roots = config.get("trusted_roots")
        if _trusted_roots is None:
            # Must be trust anchor then
            self.trusted_roots = {}
        elif isinstance(_trusted_roots, str):
            self.trusted_roots = json.loads(open(_trusted_roots).read())
        else:
            self.trusted_roots = _trusted_roots

        # Store own keys in the key jar under the entity's ID
        self.keyjar.import_jwks(self.keyjar.export_jwks(private=True), issuer_id=self.entity_id)

        for iss, jwks in self.trusted_roots.items():
            self.keyjar.import_jwks(jwks, iss)

        if authority_hints is not None:
            self.authority_hints = authority_hints
        else:
            _hints = config.get("authority_hints")
            if _hints is None:
                print(f"{_hints}, {self.trusted_roots}")
                # if self.trusted_roots != {}:
                #     raise ConfigurationError("Missing authority_hints specification")
                self.authority_hints = []
            elif isinstance(_hints, str):
                self.authority_hints = json.loads(open(_hints).read())
            else:
                self.authority_hints = _hints

        if priority:
            self.tr_priority = priority
        elif 'priority' in config:
            self.tr_priority = config["priority"]
        else:
            self.tr_priority = sorted(set(self.trusted_roots.keys()))

        _sstm = config.get("self_signed_trust_marks")
        if _sstm:
            self.signed_trust_marks = create_self_signed_trust_marks(entity_id=self.entity_id,
                                                                     keyjar=self.keyjar,
                                                                     spec=_sstm)

    def create_entity_statement(self, iss, sub, key_jar=None, metadata=None, metadata_policy=None,
                                authority_hints=None, lifetime=0, jwks=None, **kwargs):
        if jwks:
            kwargs["jwks"] = jwks
        else:
            if "keys" in kwargs:
                kwargs["jwks"] = {'keys': kwargs["keys"]}
                del kwargs["keys"]

        key_jar = key_jar or self.keyjar

        if not authority_hints:
            authority_hints = self.authority_hints
        if not lifetime:
            lifetime = self.default_lifetime

        return create_entity_statement(iss, sub, key_jar=key_jar, metadata=metadata,
                                       metadata_policy=metadata_policy,
                                       authority_hints=authority_hints, lifetime=lifetime, **kwargs)

    def make_configuration_statement(self):
        _metadata = self.server_get("metadata")
        kwargs = {}
        if self.authority_hints:
            kwargs["authority_hints"] = self.authority_hints
        if self.trust_marks:
            kwargs["trust_marks"] = self.trust_marks

        return self.create_entity_statement(iss=self.entity_id, sub=self.entity_id,
                                            metadata=_metadata, **kwargs)


class FederationEntity(object):
    name = "federation_entity"

    def __init__(self,
                 entity_id: str = "",
                 config: Optional[Union[dict, Configuration]] = None,
                 httpc: Optional[Any] = None,
                 cwd: Optional[str] = '',
                 httpc_params: Optional[dict] = None):

        if config is None:
            config = {}

        if httpc is None:
            httpc = request

        if httpc_params is None:
            httpc_params = config.get("httpc_params", {})

        if not entity_id:
            entity_id = config.get("entity_id")

        self.context = FederationContext(config=config, entity_id=entity_id,
                                         server_get=self.server_get)

        self.collector = Collector(trust_anchors=self.context.trusted_roots,
                                   http_cli=httpc, cwd=cwd, httpc_params=httpc_params)

        if config.get("entity_id") is None:
            config['entity_id'] = entity_id

        if 'endpoint' in config:
            self.endpoint = do_endpoints(config, self.server_get)
        else:
            self.endpoint = {}

    def collect_statement_chains(self, entity_id, statement):
        return self.collector.collect_superiors(entity_id, statement)

    def eval_chains(self, chains, entity_type='', apply_policies=True):
        """

        :param chains: A list of lists of signed JWT
        :param entity_type: The leafs entity type
        :param apply_policies: Apply metadata policies from the list on the the metadata of the
            leaf entity
        :return: List of TrustChain instances
        """
        _context = self.context
        if not entity_type:
            entity_type = _context.opponent_entity_type

        return [eval_chain(c, _context.keyjar, entity_type, apply_policies) for c in chains]

    def get_configuration_information(self, subject_id):
        return self.collector.get_configuration_information(subject_id)

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

    def collect_trust_chains(self, self_signed_statement, metadata_type):
        """

        :param self_signed_statement: A Self signed Entity Statement
        :param metadata_type: One of the metadata types defined in the specification
        :return:
        """
        payload = self.get_payload(self_signed_statement)

        # collect trust chains
        _tree = self.collect_statement_chains(payload['iss'], payload)
        _node = {payload['iss']: (self_signed_statement, _tree)}
        _chains = branch2lists(_node)
        logger.debug("%s chains", len(_chains))

        # verify the trust paths and apply policies
        return [eval_chain(c, self.context.keyjar, metadata_type) for c in _chains]

    def server_get(self, what, *arg):
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
        for key, item in self.endpoint.items():
            if key in ["fetch", "list", "status", "evaluate"]:
                endpoints[f"federation_{key}_endpoint"] = item.full_path
        for attr in message.FederationEntity.c_param.keys():
            if attr in _config:
                metadata[attr] = _config[attr]
            elif attr in endpoints:
                metadata[attr] = endpoints[attr]
        return {"federation_entity": metadata}

    def get_metadata(self):
        _config = self.context.config
        return self.federation_endpoint_metadata()

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_entity(self):
        return self

    def dump(self):
        return {
            "context": self.context.dump(),
            "collector": self.collector.dump()
        }

    def load(self, dump):
        self.collector.load(dump.get("collector", {}))
        self.context.load(dump.get("context", {}))

    def get_client_id(self):
        return self.context.entity_id


def create_federation_entity(entity_id, httpc=None, httpc_params=None, cwd="", **kwargs):
    args = {"httpc_params": httpc_params}
    _conf = {}

    _key_conf = kwargs.get("keys")
    if _key_conf:
        kwargs["key_conf"] = _key_conf

    for param in ['trusted_roots', 'authority_hints']:
        try:
            _conf[param] = load_json(kwargs[param])
        except KeyError:
            pass

    for param in ['entity_type', 'priority', 'opponent_entity_type',
                  'registration_type', 'cwd', 'endpoint']:
        try:
            _conf[param] = kwargs[param]
        except KeyError:
            pass

    for _key in ['key_conf', 'db_conf', 'issuer']:
        _value = kwargs.get(_key)
        if _value:
            _conf[_key] = _value

    if _conf:
        _conf['httpc_params'] = args['httpc_params']
        args['config'] = _conf

    federation_entity = FederationEntity(entity_id, httpc=httpc, cwd=cwd, **args)

    add_ons = kwargs.get("add_on")
    if add_ons:
        for spec in add_ons.values():
            if isinstance(spec["function"], str):
                _func = importer(spec["function"])
            else:
                _func = spec["function"]
            _func(federation_entity, **spec["kwargs"])

    return federation_entity
