from typing import List
from typing import Optional

from fedservice.build_entity import FederationEntityBuilder
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS


def main(entity_id: str,
         authority_hints: Optional[List[str]],
         trust_anchors: Optional[dict],
         preference: Optional[dict] = None):
    entity = FederationEntityBuilder(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    entity.add_services()
    entity.add_functions()
    entity.add_endpoints({}, **LEAF_ENDPOINT)

    federation_entity = FederationEntity(**entity.conf)
    for id, jwk in trust_anchors.items():
        federation_entity.keyjar.import_jwks(jwk, id)

    federation_entity.function.trust_chain_collector.trust_anchors = trust_anchors

    return federation_entity
