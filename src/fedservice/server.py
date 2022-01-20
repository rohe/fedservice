from typing import Any
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from oidcop import server

from fedservice.configure import FedOpConfiguration
from fedservice.entity import FederationEntity


class Server(server.Server):
    def __init__(self,
                 conf: Union[dict, FedOpConfiguration],
                 keyjar: Optional[KeyJar] = None,
                 cwd: Optional[str] = "",
                 cookie_handler: Optional[Any] = None,
                 httpc: Optional[Any] = None
                 ):
        server.Server.__init__(self, conf=conf, keyjar=keyjar, cwd=cwd,
                               cookie_handler=cookie_handler, httpc=httpc)

        fed_conf = conf["federation"]
        federation_entity = FederationEntity(httpc=httpc, config=fed_conf)

        self.server_get("endpoint_context").federation_entity = federation_entity
