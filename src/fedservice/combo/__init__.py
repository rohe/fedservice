from typing import Any
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.configure import Configuration
from idpyoidc.node import Unit
from idpyoidc.server.util import execute
from requests import request


class Combo(Unit):
    name = 'root'

    def __init__(self,
                 config: Union[dict, Configuration],
                 httpc: Optional[object] = None,
                 entity_id: Optional[str] = '',
                 keyjar: Optional[Union[KeyJar, bool]] = None,
                 httpc_params: Optional[dict] = None
                 ):
        self.entity_id = entity_id or config.get('entity_id')
        if not httpc_params:
            httpc_params = self._get_httpc_params(config)

        Unit.__init__(self, config=config, httpc=httpc, issuer_id=self.entity_id, keyjar=keyjar,
                      httpc_params=httpc_params)
        self._part = {}
        for key, spec in config.items():
            if isinstance(spec, dict) and 'class' in spec:
                if httpc_params:
                    self._add_httpc_params(spec, httpc_params)
                self._part[key] = execute(spec, upstream_get=self.unit_get,
                                          entity_id=self.entity_id, httpc=httpc)

    def _get_httpc_params(self, config):
        return config.get("httpc_params")

    def _add_httpc_params(self, spec, httpc_params):
        spec_kwargs = spec.get("kwargs", {})
        if "config" in spec_kwargs:
            if httpc_params and "httpc_params" not in spec_kwargs["config"]:
                spec_kwargs["config"]["httpc_params"] = httpc_params
        else:
            if "httpc_params" not in spec_kwargs:
                spec_kwargs["httpc_params"] = httpc_params

    def __getitem__(self, item):
        if item in self._part:
            return self._part[item]
        else:
            return None

    def __setitem__(self, key, value):
        self._part[key] = value

    def get_entity_types(self):
        return list(self._part.keys())

    def keys(self):
        return self._part.keys()

    def items(self):
        return self._part.items()

    def get(self, item: Optional[str], default:Optional[Any] = None):
        if item in self._part:
            return self._part[item]
        else:
            return default

class FederationCombo(Combo):

    def __init__(self,
                 config: Union[dict, Configuration],
                 httpc: Optional[object] = None,
                 entity_id: Optional[str] = '',
                 keyjar: Optional[Union[KeyJar, bool]] = None,
                 httpc_params: Optional[dict] = None
                 ):
        if httpc is None:
            httpc = request

        if 'keyjar' not in config and 'key_conf' not in config:
            Combo.__init__(self, config=config, httpc=httpc, entity_id=entity_id, keyjar=False,
                           httpc_params=httpc_params)
        else:
            Combo.__init__(self, config=config, httpc=httpc, entity_id=entity_id, keyjar=keyjar,
                           httpc_params=httpc_params)

    def _get_httpc_params(self, config):
        _hp = config.get("httpc_params")
        if _hp:
            return _hp
        return config["federation_entity"].get("httpc_params")

    def get_metadata(self):
        res = {}
        for item in self._part.values():
            res.update(item.get_metadata())
        return res

    def get_preferences(self):
        return self.get_metadata()

    def get_federation_entity(self):
        return self._part["federation_entity"]

    def get_attribute(self, attr, *args):
        val = getattr(self, attr, None)
        if val:
            return val

        cntx = getattr(self, 'context', None)
        if cntx:
            val = getattr(cntx, attr, None)
            if val:
                return val

        if attr == "keyjar":
            _fed_entity = self.get_federation_entity()
            return _fed_entity.keyjar

    def get_keyjar(self):
        if self.keyjar:
            return self.keyjar
        else:
            return self.get_federation_entity().keyjar
