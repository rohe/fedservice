#!/usr/bin/env python3
import logging
import os

from cryptojwt.jwk import pems_to_x5c
from flask import Flask

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

FOLDER = os.path.dirname(os.path.realpath(__file__))


def init_sign_service(app):
    _config = app.config.get('CONFIG')
    _server_info_config = _config['server_info']

    signing_service = SigningService(_server_info_config, cwd=FOLDER)

    return signing_service


def init_app(name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    app.config.from_pyfile(os.path.join(FOLDER, 'conf.py'))

    try:
        from .views import sigserv_views
    except ImportError:
        from views import sigserv_views

    app.register_blueprint(sigserv_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.signing_service = init_sign_service(app)

    return app


if __name__ == "__main__":
    app = init_app(NAME)
    logging.basicConfig(level=logging.DEBUG)

    _conf = app.config.get('CONFIG')
    web_conf = _conf['webserver']
    ssl_context = (web_conf['cert'].format(dir_path),
                   web_conf['key'].format(dir_path))

    app.signing_service.cwd = dir_path

    with open(web_conf['cert'].format(dir_path), 'r') as fp:
        pem = fp.read()
        app.signing_service.x5c = pems_to_x5c([pem])

    app.run(host=app.config.get('DOMAIN'), port=app.config.get('PORT'),
            debug=True, ssl_context=ssl_context)
