from typing import Optional
from typing import Union

from requests import request
from idpyoidc.configure import Configuration
from idpyoidc.server.util import execute

from fedservice.node import Unit


class Combo(Unit):
    name = 'root'

    def __init__(self, config: Union[dict, Configuration], httpc: Optional[object] = None):
        Unit.__init__(self, config=config, httpc=httpc)
        self._part = {}
        for key, spec in config.items():
            if 'class' in spec:
                self._part[key] = execute(spec, upstream_get=self.unit_get,
                                          entity_id=self.entity_id, httpc=httpc)

    def __getitem__(self, item):
        return self._part[item]

    def __setitem__(self, key, value):
        self._part[key] = value

    def keys(self):
        return self._part.keys()

    def items(self):
        return self._part.items()


class FederationCombo(Combo):
    def __init__(self, config: Union[dict, Configuration], httpc: Optional[object] = None):
        if httpc is None:
            httpc = request

        Combo.__init__(self, config=config, httpc=httpc)

    def get_metadata(self):
        res = {}
        for item in self._part.values():
            res.update(item.get_metadata())
        return res
