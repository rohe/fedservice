"""Configuration management for Signing Service"""

from typing import Dict

from oidcrp.logging import configure_logging
from oidcrp.util import get_http_params
from oidcrp.util import load_yaml_config
from oidcrp.util import lower_or_upper

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from oidcendpoint import rndstr as rnd_token


class Configuration:
    """Signing Service Configuration"""

    def __init__(self, conf: Dict) -> None:
        self.logger = configure_logging(config=conf.get('logging')).getChild(__name__)

        # server info
        self.domain = lower_or_upper(conf, "domain")
        self.port = lower_or_upper(conf, "port")

        # HTTP params
        _params = get_http_params(conf.get("http_params"))
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

    @classmethod
    def create_from_config_file(cls, filename: str):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename))
