from typing import Any
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from oidcop.configure import ASConfiguration
from oidcop.configure import OPConfiguration
from oidcop.server import Server

from fedservice.entity import FederationEntity


class FederationServer(Server):
    def __init__(
            self,
            conf: Union[dict, OPConfiguration, ASConfiguration],
            keyjar: Optional[KeyJar] = None,
            cwd: Optional[str] = "",
            cookie_handler: Optional[Any] = None,
            httpc: Optional[Any] = None):
        Server.__init__(self, conf=conf, keyjar=keyjar, cwd=cwd, cookie_handler=cookie_handler,
                        httpc=httpc)

        fed_conf = conf.get("federation")
        if fed_conf:
            self.endpoint_context.federation_entity = FederationEntity(config=fed_conf,
                                                                       httpc=httpc,
                                                                       cwd=cwd)
