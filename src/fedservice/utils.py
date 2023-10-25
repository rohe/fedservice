import logging
from typing import List
from typing import Optional

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import federation_endpoints
from fedservice.defaults import federation_functions
from fedservice.defaults import federation_services
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
                        item_args: Optional[dict] = None) -> dict:
    _key_conf = key_config or {"key_defs": DEFAULT_KEY_DEFS}

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
                func(args=_args, kwargs_spec=kwargs_spec, **federation_services(*items))
            elif name == "function":
                func(args=_args, kwargs_spec=kwargs_spec, **federation_functions(*items))
            elif name == "endpoint":
                func(args=_args, kwargs_spec=kwargs_spec, **federation_endpoints(*items))
        elif services == []:
            pass
        else:  # There is a difference between None == default and [] which means none
            func(args=_args, kwargs_spec=kwargs_spec)

    return entity.conf


def make_federation_entity(entity_id: str,
                           key_config: Optional[dict] = None,
                           authority_hints: Optional[List[str]] = None,
                           trust_anchors: Optional[dict] = None,
                           preference: Optional[dict] = None,
                           endpoints: Optional[List[str]] = None,
                           services: Optional[List[str]] = None,
                           functions: Optional[List[str]] = None,
                           trust_marks: Optional[dict] = None,
                           init_kwargs: Optional[dict] = None,
                           item_args: Optional[dict] = None
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
        item_args=item_args
    )

    fe = FederationEntity(**_config)
    if trust_anchors:
        for id, jwk in trust_anchors.items():
            fe.keyjar.import_jwks(jwk, id)

        fe.function.trust_chain_collector.trust_anchors = trust_anchors

    return fe


def make_federation_combo(entity_id: str,
                          key_config: Optional[dict] = None,
                          authority_hints: Optional[List[str]] = None,
                          trust_anchors: Optional[dict] = None,
                          preference: Optional[dict] = None,
                          additional_conf: Optional[dict] = None,
                          endpoints: Optional[List[str]] = None,
                          services: Optional[List[str]] = None,
                          functions: Optional[List[str]] = None
                          ):
    _config = build_entity_config(
        entity_id=entity_id,
        key_config=key_config,
        authority_hints=authority_hints,
        preference=preference,
        endpoints=endpoints,
        services=services,
        functions=functions
    )

    entity_config = {
        'entity_id': entity_id,
        "federation_entity": {
            'class': FederationEntity,
            'kwargs': _config
        }
    }
    entity_config.update(additional_conf)
    combo = FederationCombo(entity_config)

    if trust_anchors:
        for id, jwk in trust_anchors.items():
            combo["federation_entity"].keyjar.import_jwks(jwk, id)

        combo["federation_entity"].function.trust_chain_collector.trust_anchors = trust_anchors

    return combo
