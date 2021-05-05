"""Configuration management for Signing Service"""
import logging
from typing import Dict
from typing import List
from typing import Optional

from oidcop.configure import Base
from oidcop.configure import OPConfiguration
from oidcrp.logging import configure_logging
from oidcrp.util import get_http_params
from oidcrp.util import lower_or_upper

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from oidcop import rndstr as rnd_token


class RPConfiguration:
    """Signing Service Configuration"""

    def __init__(self, conf: Dict) -> None:
        self.logger = configure_logging(config=conf.get('logging')).getChild(__name__)

        # server info
        self.domain = lower_or_upper(conf, "domain")
        self.port = lower_or_upper(conf, "port")

        # HTTP params
        _params = get_http_params(conf.get("httpc_params"))
        if _params:
            self.httpc_params = _params
        else:
            _params = {'verify', lower_or_upper(conf, "verify_ssl", True)}

        # web server config
        self.web_conf = lower_or_upper(conf, "webserver")

        srv_info = lower_or_upper(conf, "server_info", {})
        for entity, spec in srv_info.items():
            for key, arg in spec.items():
                if key == "kwargs":
                    _kw_args = {}
                    for attr, val in arg.items():
                        if attr in ["entity_id_pattern", "url_prefix"]:
                            _kw_args[attr] = val.format(domain=self.domain, port=self.port)
                        else:
                            _kw_args[attr] = val

                    spec["kwargs"] = _kw_args

        self.server_info = srv_info


DEFAULT_CONFIG = {
    "keys": {
        "private_path": "private/fed_keys.json",
        "key_defs": [
            {
                "type": "RSA",
                "use": [
                    "sig"
                ]
            },
            {
                "type": "EC",
                "crv": "P-256",
                "use": [
                    "sig"
                ]
            }
        ],
        "public_path": "static/fed_keys.json",
        "read_only": False
    },
    "authority_hints": "authority_hints.json",
    "trusted_roots": "trusted_roots.json"
}


class FedConfiguration(Base):
    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0
                 ):
        Base.__init__(self, conf, base_path, file_attributes)

        self.entity_id = ""
        self.keys = None
        self.authority_hints = ""
        self.trusted_roots = ""
        self.priority = {}
        self.entity_type = ""
        self.opponent_entity_type = ""

        for key in self.__dict__.keys():
            _val = conf.get(key)
            if not _val and key in DEFAULT_CONFIG:
                _val = DEFAULT_CONFIG[key]
            if not _val:
                continue

            if key in ["entity_id"]:
                if '{domain}' in _val:
                    setattr(self, key, _val.format(domain=domain, port=port))
                else:
                    setattr(self, key, _val)
            else:
                setattr(self, key, _val)


class FedOpConfiguration(OPConfiguration):
    def __init__(self,
                 conf: Dict,
                 base_path: Optional[str] = '',
                 domain: Optional[str] = "127.0.0.1",
                 port: Optional[int] = 80,
                 file_attributes: Optional[List[str]] = None,
                 ):
        OPConfiguration.__init__(self, conf, base_path, domain, port, file_attributes)

        fed_conf = conf.get("federation")
        if fed_conf:
            self.federation = FedConfiguration(fed_conf)
        else:
            self.federation = None


class Configuration(Base):
    """Server Configuration"""

    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0
                 ):
        Base.__init__(self, conf, base_path, file_attributes)

        log_conf = conf.get('logging')
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger('oidcop')

        self.webserver = conf.get("webserver", {})

        if domain:
            args = {"domain": domain}
        else:
            args = {"domain": conf.get("domain", "127.0.0.1")}

        if port:
            args["port"] = port
        else:
            args["port"] = conf.get("port", 80)

        self.op = FedOpConfiguration(conf["op"]["server_info"], **args)
