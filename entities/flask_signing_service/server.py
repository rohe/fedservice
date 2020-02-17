#!/usr/bin/env python3
import logging
import os
import sys

from cryptojwt.jwk import pems_to_x5c
from flask import Flask
from oidcop.utils import create_context
from oidcop.utils import load_yaml_config
from oidcop.utils import lower_or_upper

from fedservice.op.signing_service import SigningService

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


def init_sign_service(app):
    _server_info_config = app.config.get('server_info')

    signing_service = SigningService(_server_info_config, cwd=dir_path)

    return signing_service


def init_app(config_file, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    if config_file.endswith('.yaml'):
        app.config.update(load_yaml_config(config_file))
    elif config_file.endswith('.py'):
        app.config.from_pyfile(os.path.join(dir_path, config_file))
    else:
        raise ValueError('Unknown configuration format')

    try:
        from .views import sigserv_views
    except ImportError:
        from views import sigserv_views

    app.register_blueprint(sigserv_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.signing_service = init_sign_service(app)

    return app


if __name__ == "__main__":
    app = init_app(sys.argv[1], NAME)
    logging.basicConfig(level=logging.DEBUG)

    web_conf = app.config.get('webserver')

    ssl_context = create_context(dir_path, web_conf)

    app.signing_service.cwd = dir_path
    _cert = "{}/{}".format(dir_path, lower_or_upper(web_conf, "server_cert"))

    with open(_cert.format(dir_path), 'r') as fp:
        pem = fp.read()
        app.signing_service.x5c = pems_to_x5c([pem])

    app.run(host=web_conf.get('domain'), port=web_conf.get('port'),
            debug=True, ssl_context=ssl_context)
