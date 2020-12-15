#!/usr/bin/env python3
import logging
import os
import sys

from cryptojwt import KeyJar
from cryptojwt.jwk import pems_to_x5c
from flask import Flask
from oidcop.utils import create_context
from oidcop.utils import lower_or_upper

from fedservice.configure import Configuration
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
    _server_info_config = app.fss_config.server_info

    signing_service = SigningService(_server_info_config, cwd=dir_path)

    return signing_service


def init_app(config_file, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    app.fss_config = Configuration.create_from_config_file(config_file)

    try:
        from .views import sigserv_views
    except ImportError:
        from views import sigserv_views

    app.register_blueprint(sigserv_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.signing_service = init_sign_service(app)

    return app


if __name__ == "__main__":
    domain = '127.0.0.1'
    op_port = 5000
    rp_spec = [("../flask_rp/static/fed_keys.json", 4000),
               ("../flask_rp/static/fed_keys_auto.json", 4001)]

    # Copy dynamically created files to there places in the base_data information tree.
    key_jar = KeyJar()
    key_jar.import_jwks_from_file("../flask_op/static/fed_keys.json", "")
    _jwks = key_jar.export_jwks_as_json(issuer_id="")
    with open('base_data/umu.se/https%3A%2F%2F{}%3A{}/jwks.json'.format(domain,op_port), "w") as fp:
        fp.write(_jwks)

    for _key_file, _port in rp_spec:
        if os.path.isfile(_key_file):
            key_jar = KeyJar()
            key_jar.import_jwks_from_file(_key_file, "")
            _jwks = key_jar.export_jwks_as_json(issuer_id="")
            _file = 'base_data/lu.se/https%3A%2F%2F{}%3A{}%2Flocal/jwks.json'.format(domain,_port)
            with open(_file, "w") as fp:
                fp.write(_jwks)

    app = init_app(sys.argv[1], NAME)
    logging.basicConfig(level=logging.DEBUG)

    web_conf = app.fss_config.web_conf

    ssl_context = create_context(dir_path, web_conf)

    app.signing_service.cwd = dir_path
    _cert = "{}/{}".format(dir_path, lower_or_upper(web_conf, "server_cert"))

    with open(_cert.format(dir_path), 'r') as fp:
        pem = fp.read()
    app.signing_service.x5c = pems_to_x5c([pem])

    app.run(host=web_conf.get('domain'), port=web_conf.get('port'),
            debug=web_conf.get('debug', True), ssl_context=ssl_context)
