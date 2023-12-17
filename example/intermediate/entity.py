#!/usr/bin/env python3
import json
import os
import sys

from flask.app import Flask
from idpyoidc.client.util import lower_or_upper
from idpyoidc.logging import configure_logging
from idpyoidc.ssl_context import create_context
from idpyoidc.util import load_config_file

from fedservice.utils import make_federation_combo

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')

def _import(val):
    with open(val[len("file:"):], "r") as fp:
        _dat = fp.read()
        if val.endswith('.json'):
            return json.loads(_dat)
        elif val.endswith(".py"):
            return _dat

    raise ValueError("Unknown file type")


def load_values_from_file(config):
    res = {}
    for key, val in config.items():
        if isinstance(val, str) and val.startswith("file:"):
            res[key] = _import(val)
        elif isinstance(val, dict):
            res[key] = load_values_from_file(val)
        elif isinstance(val, list):
            _list = []
            for v in val:
                if isinstance(v, dict):
                    _list.append(load_values_from_file(v))
                elif isinstance(val, str) and val.startswith("file:"):
                    res[key] = _import(val)
                else:
                    _list.append(v)
            res[key] = _list

    for k, v in res.items():
        config[k] = v

    return config

def init_app(config_file, name=None, **kwargs) -> Flask:
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    try:
        from .views import intermediate
    except ImportError:
        from views import intermediate

    app.register_blueprint(intermediate)
    # Initialize the oidc_provider after views to be able to set correct urls
    app.cnf = load_config_file(config_file)
    app.cnf = load_values_from_file(app.cnf)
    app.cnf["cwd"] = dir_path
    app.server = make_federation_combo(**app.cnf["entity"])

    return app


if __name__ == "__main__":
    print(sys.argv)
    name = sys.argv[1]
    conf = sys.argv[2]
    template_dir = os.path.join(dir_path, 'templates')
    app = init_app(conf, name, template_folder=template_dir)
    if "logging" in app.cnf:
        configure_logging(config=app.cnf["logging"])
    _web_conf = app.cnf["webserver"]
    context = create_context(dir_path, _web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))

    print('Listening on {}:{}'.format(_web_conf.get('domain'), _web_conf.get('port')))
    # app.rph.federation_entity.collector.web_cert_path = _cert
    app.run(host=_web_conf.get('domain'), port=_web_conf.get('port'),
            debug=_web_conf.get("debug"), ssl_context=context)
