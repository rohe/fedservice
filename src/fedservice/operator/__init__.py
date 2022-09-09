#
from typing import Optional
from typing import Union

from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import init_key_jar
from idpyoidc.client.configure import get_configuration
from idpyoidc.configure import Configuration
from idpyoidc.impexp import ImpExp
from idpyoidc.util import instantiate


class Player(ImpExp):
    parameter = {"keyjar": KeyJar, "issuer": None}

    def __int__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            jwks_uri: Optional[str] = "",
            httpc_params: Optional[dict] = None,
            entity_id: Optional[str] = "",
    ):
        ImpExp.__init__(self)
        config = get_configuration(config)

        self.keyjar = self._keyjar(keyjar, conf=config, entity_id=entity_id)
        self.object = {entity_type: instantiate(args['class'], **args["kwargs"]) for
                       entity_type, args in config.items()}

    def _keyjar(self, keyjar=None, conf=None, entity_id=""):
        if keyjar is None:
            if "keys" in conf:
                keys_args = {k: v for k, v in conf["keys"].items() if k != "uri_path"}
                _keyjar = init_key_jar(**keys_args)
            elif "key_conf" in conf and conf["key_conf"]:
                keys_args = {k: v for k, v in conf["key_conf"].items() if k != "uri_path"}
                _keyjar = init_key_jar(**keys_args)
            else:
                _keyjar = KeyJar()
                if "jwks" in conf:
                    _keyjar.import_jwks(conf["jwks"], "")

            if "" in _keyjar and entity_id:
                # make sure I have the keys under my own name too (if I know it)
                _keyjar.import_jwks_as_json(_keyjar.export_jwks_as_json(True, ""), entity_id)

            _httpc_params = conf.get("httpc_params")
            if _httpc_params:
                _keyjar.httpc_params = _httpc_params

            return _keyjar
        else:
            return keyjar

