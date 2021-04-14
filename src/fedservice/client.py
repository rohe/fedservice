from typing import Any
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from oidcrp import entity

from fedservice import FederationEntity
from fedservice.configure import Configuration


class Client(entity.Entity):
    def __init__(self,
                 conf: Union[dict, Configuration],
                 keyjar: Optional[KeyJar] = None,
                 httpc: Optional[Any] = None
                 ):
        entity.Entity.__init__(self, config=conf, keyjar=keyjar)

        fed_conf = conf["federation"]
        federation_entity = FederationEntity(
            httpd=httpc,
            config=fed_conf
        )

        self.client_get("service_context").federation_entity = federation_entity
