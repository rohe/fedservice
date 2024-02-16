import logging
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.server.util import execute

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import FEDERATION_ENDPOINTS
from fedservice.defaults import federation_endpoints
from fedservice.defaults import federation_functions
from fedservice.defaults import federation_services
from fedservice.defaults import SERVICES
from fedservice.entity import FederationEntity

logger = logging.getLogger(__name__)


def statement_is_expired(item):
    now = utc_time_sans_frac()
    if "exp" in item:
        if item["exp"] < now:
            logger.debug(f'is_expired: {item["exp"]} < {now}')
            return True

    return False


def build_entity_config(entity_id: str,
                        key_config: Optional[dict] = None,
                        authority_hints: Optional[List[str]] = None,
                        preference: Optional[dict] = None,
                        endpoints: Optional[List[str]] = None,
                        services: Optional[List[str]] = None,
                        functions: Optional[List[str]] = None,
                        init_kwargs: Optional[dict] = None,
                        item_args: Optional[dict] = None,
                        subordinate: Optional[dict] = None,
                        httpc_params: Optional[dict] = None,
                        persistence: Optional[dict] = None,
                        trust_mark_server: Optional[dict] = None
                        ) -> dict:
    _key_conf = key_config or {"key_defs": DEFAULT_KEY_DEFS}

    if authority_hints:
        if "class" in authority_hints and "kwargs" in authority_hints:
            authority_hints = execute(authority_hints)

    entity = FederationEntityBuilder(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_conf=_key_conf
    )
    for name, items in [("service", services), ("function", functions), ("endpoint", endpoints)]:
        func = getattr(entity, f"add_{name}s")

        if init_kwargs:
            kwargs_spec = init_kwargs.get(name, {})
        else:
            kwargs_spec = None

        if item_args:
            _args = item_args.get(name, {})
        else:
            _args = {}

        if items:
            if name == "service":
                if isinstance(items, dict):
                    _filtered_spec = {k: v for k, v in items.items() if k in SERVICES}
                    func(args=_args, kwargs_spec=kwargs_spec, **_filtered_spec)
                else:
                    func(args=_args, kwargs_spec=kwargs_spec, **federation_services(*items))
            elif name == "function":
                func(args=_args, kwargs_spec=kwargs_spec, **federation_functions(*items))
            elif name == "endpoint":
                if isinstance(items, dict):
                    _filtered_spec = {k: v for k, v in items.items() if k in FEDERATION_ENDPOINTS}
                    func(args=_args, kwargs_spec=kwargs_spec, **_filtered_spec)
                else:
                    func(args=_args, kwargs_spec=kwargs_spec, **federation_endpoints(*items))
        elif services == []:
            pass
        else:  # There is a difference between None == default and [] which means none
            func(args=_args, kwargs_spec=kwargs_spec)

    if httpc_params:
        entity.conf["httpc_params"] = httpc_params
    if persistence:
        entity.conf["persistence"] = persistence

    return entity.conf


def make_federation_entity(entity_id: str,
                           key_config: Optional[dict] = None,
                           authority_hints: Optional[List[str]] = None,
                           trust_anchors: Optional[dict] = None,
                           preference: Optional[dict] = None,
                           endpoints: Optional[List[str]] = None,
                           services: Optional[Union[List[str], dict]] = None,
                           functions: Optional[Union[List[str], dict]] = None,
                           trust_marks: Optional[list] = None,
                           init_kwargs: Optional[dict] = None,
                           item_args: Optional[dict] = None,
                           subordinate: Optional[dict] = None,
                           metadata_policy: Optional[dict] = None,
                           httpc_params: Optional[dict] = None,
                           persistence: Optional[dict] = None,
                           trust_mark_server: Optional[dict] = None,
                           client_authn_methods: Optional[list] = None
                           ):
    _config = build_entity_config(
        entity_id=entity_id,
        key_config=key_config,
        authority_hints=authority_hints,
        preference=preference,
        endpoints=endpoints,
        services=services,
        functions=functions,
        init_kwargs=init_kwargs,
        item_args=item_args,
        httpc_params=httpc_params,
        persistence=persistence
    )

    fe = FederationEntity(client_authn_methods=client_authn_methods, **_config)
    if trust_anchors:
        for id, jwk in trust_anchors.items():
            fe.keyjar.import_jwks(jwk, id)

        fe.function.trust_chain_collector.trust_anchors = trust_anchors

    if subordinate:
        if "class" in subordinate and "kwargs" in subordinate:
            fe.server.subordinate = execute(subordinate)
        else:
            for id, info in subordinate.items():
                fe.server.subordinate[id] = info

    if metadata_policy:
        for id, info in metadata_policy.items():
            fe.server.policy[id] = info

    if trust_marks:
        fe.context.trust_marks = trust_marks

    return fe


def make_federation_combo(entity_id: str,
                          key_config: Optional[dict] = None,
                          authority_hints: Optional[List[str]] = None,
                          trust_anchors: Optional[dict] = None,
                          preference: Optional[dict] = None,
                          entity_type: Optional[dict] = None,
                          endpoints: Optional[List[str]] = None,
                          services: Optional[List[str]] = None,
                          functions: Optional[List[str]] = None,
                          subordinate: Optional[dict] = None,
                          metadata_policy: Optional[dict] = None,
                          httpc_params: Optional[dict] = None,
                          init_kwargs: Optional[dict] = None,
                          item_args: Optional[dict] = None,
                          trust_marks: Optional[dict] = None,
                          persistence: Optional[dict] = None,
                          trust_mark_issuers: Optional[dict] = None,
                          trust_mark_owner: Optional[dict] = None,
                          trust_mark_server: Optional[dict] = None
                          ):
    _config = build_entity_config(
        entity_id=entity_id,
        key_config=key_config,
        authority_hints=authority_hints,
        preference=preference,
        endpoints=endpoints,
        services=services,
        functions=functions,
        httpc_params=httpc_params,
        init_kwargs=init_kwargs,
        item_args=item_args,
        persistence=persistence
    )

    if entity_type:
        entity_config = {
            'entity_id': entity_id,
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': _config
            }
        }
        entity_config.update(entity_type)
        if httpc_params:
            entity_config["httpc_params"] = httpc_params

        entity = FederationCombo(entity_config)
        federation_entity = entity["federation_entity"]
    else:
        entity = FederationEntity(trust_mark_server=trust_mark_server, **_config)
        federation_entity = entity

    if trust_anchors:
        if "class" in trust_anchors:
            trust_anchors = execute(trust_anchors)

        for id, jwk in trust_anchors.items():
            federation_entity.keyjar.import_jwks(jwk, id)

        federation_entity.function.trust_chain_collector.trust_anchors = trust_anchors

    if subordinate:
        if "class" in subordinate:
            federation_entity.server.subordinate = execute(subordinate)
        else:
            for id, info in subordinate.items():
                federation_entity.server.subordinate[id] = info

    if metadata_policy:
        for id, info in metadata_policy.items():
            federation_entity.server.policy[id] = info

    if trust_marks:
        federation_entity.context.trust_marks = trust_marks

    if trust_mark_issuers:
        if "class" in trust_mark_issuers:
            federation_entity.context.trust_mark_issuers = execute(trust_mark_issuers)
        else:
            federation_entity.context.trust_mark_issuers = trust_mark_issuers

    if trust_mark_owner:
        if "class" in trust_mark_owner:
            federation_entity.context.trust_mark_owner = execute(trust_mark_owner)
        else:
            federation_entity.context.trust_mark_owner = trust_mark_owner

    return entity
