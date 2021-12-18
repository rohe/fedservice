#!/usr/bin/env python3
import logging
import os
import sys
from typing import Optional
from typing import Tuple

from cryptojwt import KeyJar
from cryptojwt.utils import importer
from flask import Flask
from oidcmsg.configure import Configuration
from oidcmsg.configure import create_from_config_file
from oidcop.utils import create_context
from oidcop.utils import lower_or_upper

from fedservice.configure import FedSigServConfiguration

NAME = 'sign_serv'

LOGGER = logging.getLogger("")
LOGFILE_NAME = '{}.log'.format(NAME)
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')


class SigningService:
    def __init__(self, conf, cwd: Optional[str] = '',
                 domain: Optional[str] = "",
                 port: Optional[int] = 0):
        self.issuer = {}
        self.wd = cwd
        self.web_cert_path = ""

        kwargs = conf["kwargs"]
        kwargs["base_path"] = self.wd

        if domain:
            kwargs["domain"] = domain
        if port:
            kwargs["port"] = port

        self.issuer = self.build_signing_service(conf["class"], **kwargs)

    def build_signing_service(self, klass, **kwargs):
        if isinstance(klass, str):
            _instance = importer(klass)(**kwargs)
        else:
            _instance = klass(**kwargs)

        return _instance


def init_app(config_file: str, name: Optional[str] = "", **kwargs) -> Tuple[Flask, Configuration]:
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    try:
        from .views import sigserv_views
    except ImportError:
        from views import sigserv_views

    app.register_blueprint(sigserv_views)

    _config = create_from_config_file(Configuration,
                                      entity_conf=[{
                                          'class': FedSigServConfiguration,
                                          'attr': 'sigsrv'
                                      }],
                                      filename=config_file)

    app.signing_service = SigningService(_config.sigsrv.server_info, cwd=dir_path,
                                         domain=_config.domain, port=_config.port)

    return app, _config


if __name__ == "__main__":
    app, _config = init_app(sys.argv[1], NAME)
    logging.basicConfig(level=logging.DEBUG)

    web_conf = _config.web_conf
    ssl_context = create_context(dir_path, web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(web_conf, "server_cert"))

    app.run(host=web_conf.get('domain'), port=web_conf.get('port'),
            debug=web_conf.get('debug', True), ssl_context=ssl_context)
