from typing import Any
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.client import entity

from fedservice.entity import FederationEntity
from fedservice.configure import FedEntityConfiguration


class Client(entity.Entity):
    def __init__(self,
                 conf: Union[dict, FedEntityConfiguration],
                 keyjar: Optional[KeyJar] = None,
                 httpc: Optional[Any] = None
                 ):
        entity.Entity.__init__(self, config=conf, keyjar=keyjar)

        fed_conf = conf["federation"]
        federation_entity = FederationEntity(
            httpc=httpc,
            config=fed_conf
        )

        self.upstream_get("context").federation_entity = federation_entity
