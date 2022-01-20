#!/usr/bin/env python3
import logging
import os

from cryptojwt import KeyJar
# from cryptojwt.jwk import pems_to_x5c
from flask import Flask
from oidcop.utils import create_context
from oidcop.utils import lower_or_upper

from fedservice.configure import FedSigServConfiguration
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

_root, _ = os.path.split(dir_path)


def key_setup():
    # Copy dynamically created files to there places in the base_data information tree.
    key_jar = KeyJar()
    key_jar.import_jwks_from_file(os.path.join(dir_path, "flask_op/static/fed_keys.json"), "")
    _jwks = key_jar.export_jwks_as_json(issuer="")
    with open('base_data/umu.se/https%3A%2F%2F127.0.0.1%3A5000/jwks.json', "w") as fp:
        fp.write(_jwks)

    for _key_file, _port in [(os.path.join(dir_path, "flask_rp/static/fed_keys.json"), 4000),
                             (os.path.join(dir_path, "flask_rp/static/fed_keys_auto.json"), 4002)]:
        if os.path.isfile(_key_file):
            key_jar = KeyJar()
            key_jar.import_jwks_from_file(_key_file, "")
            _jwks = key_jar.export_jwks_as_json(issuer="")
            _file = 'base_data/lu.se/https%3A%2F%2F127.0.0.1%3A{}/jwks.json'.format(_port)
            with open(_file, "w") as fp:
                fp.write(_jwks)


try:
    from .views import sigserv_views
except ImportError:
    from views import sigserv_views

key_setup()
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, static_url_path='')

app.fss_config = FedSigServConfiguration.create_from_config_file("conf.json")

app.register_blueprint(sigserv_views)

# Initialize the oidc_provider after views to be able to set correct urls
_server_info_config = app.fss_config.server_info
app.signing_service = SigningService(_server_info_config, cwd=dir_path)

web_conf = app.fss_config.web_conf

app.signing_service.cwd = dir_path
cert_file = lower_or_upper(web_conf, "server_cert")
if not cert_file.startswith("/"):
    _cert = "{}/{}".format(dir_path, cert_file)

# with open(cert_file, 'r') as fp:
#     pem = fp.read()
#     app.signing_service.x5c = pems_to_x5c([pem])

if __name__ == "__main__":
    web_conf = app.fss_config.web_conf
    ssl_context = create_context(dir_path, web_conf)
    app.run(host=web_conf.get('domain'), port=web_conf.get('port'),
            debug=web_conf.get('domain', True), ssl_context=ssl_context)
