import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.utils import importer
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.node import Unit
from idpyoidc.server.endpoint_context import init_service
from idpyoidc.server.util import execute

logger = logging.getLogger(__name__)


class Collection(object):

    def __init__(self, conf):
        self._db = {}
        for id, spec in conf.items():
            self._db[id] = init_service(spec)

    def add(self, id: str, tminfo: dict):
        self._db[id].add(tminfo)

    def find(self, id: str, sub: str, iat: Optional[int] = 0) -> bool:
        return self._db[id].find(sub, iat)


class ServerUnit(Unit):

    def __init__(self,
                 upstream_get: Callable = None,
                 keyjar: Optional[Union[KeyJar, bool]] = None,
                 context: Optional[OidcContext] = None,
                 config: Optional[Union[Configuration, dict]] = None,
                 httpc: Optional[object] = None,
                 httpc_params: Optional[dict] = None,
                 entity_id: Optional[str] = "",
                 preference: Optional[dict] = None,
                 key_conf: Optional[dict] = None
                 ):
        self.entity_id = entity_id or config.get('entity_id')
        _keyjar = keyjar or config.get("keyjar")
        _key_conf = key_conf or config.get('key_conf')
        if not _keyjar and not _key_conf:
            keyjar = False

        Unit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc, config=config,
                      httpc_params=httpc_params, issuer_id=self.entity_id, key_conf=key_conf)

        _per_conf = config.get("persistence", None)
        if _per_conf:
            _storage = execute(_per_conf["kwargs"]["storage"])
            _class = _per_conf["class"]
            kwargs = {"storage": _storage, "upstream_get": self.unit_get}
            if isinstance(_class, str):
                self.persistence = importer(_class)(**kwargs)
            else:
                self.persistence = _per_conf["class"](**kwargs)
