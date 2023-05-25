#!/usr/bin/env python3
import argparse
import os
import sys
from typing import Optional
from urllib.parse import urlparse

from cryptojwt.utils import importer
from flask.app import Flask
from idpyoidc.client.util import lower_or_upper
from idpyoidc.configure import Configuration
from idpyoidc.configure import create_from_config_file
from idpyoidc.server.util import execute
from idpyoidc.ssl_context import create_context

from fedservice.combo import FederationCombo
from fedservice.entity import FederationEntity

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')

def init_entity(config):
    if 'op' in config or 'rp' in config:
        _args = {}
        for _name, _cnf in {'openid_relying_party': config.rp,
                            'openid_provider':config.op,
                            'federation_entity':config.fe}.items():
            if _cnf:
                _args[_name] = {'class': _cnf['class'], 'kwargs': _cnf['kwargs']}
        return FederationCombo(_args)
    else:
        return FederationEntity(**config.fe['kwargs'])


def init_app(config, name=None, views: Optional[str] = '', **kwargs) -> Flask:
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    sys.path.insert(0, '.')
    if views:
        _views = importer(f"{views}.views")
    elif 'op' in config:
        _views = importer('op_views.views')
    elif 'rp' in config:
        _views = importer('rp_views.views')
    else:  # solely an entity
        _views = importer('entity_views.views')

    app.srv_config = config
    app.register_blueprint(_views)

    # Initialize the entity after views to be able to set correct urls
    app.server = init_entity(config)

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='FederationEntity',
        description='Starts a federation entity')

    parser.add_argument('name')
    parser.add_argument('config')
    parser.add_argument('-t', '--template_dir')
    parser.add_argument('-v', '--views')  # on/off flag

    args = parser.parse_args()

    if args.template_dir:
        template_dir = args.template_dir
    else:
        template_dir = os.path.join(dir_path, 'templates')

    config = create_from_config_file(Configuration,
                                     entity_conf=[
                                         {
                                             "class": Configuration,
                                             "attr": "fe",
                                             "path": ['configuration', "federation_entity"]
                                         },
                                         {
                                             "class": Configuration,
                                             "attr": "op",
                                             "path": ['configuration', "openid_provider"]
                                         },
                                         {
                                             "class": Configuration,
                                             "attr": "rp",
                                             "path": ['configuration', "openid_relying_party"]
                                         }
                                     ],
                                     # file_attributes=DEFAULT_FED_FILE_ATTRIBUTE_NAMES,
                                     filename=args.config)

    kwargs = {'template_folder':template_dir}
    if args.views:
        kwargs['views'] = args.views

    app = init_app(config, args.name, **kwargs)

    _web_conf = app.srv_config.web_conf
    context = create_context(dir_path, _web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))

    print('Listening on {}:{}'.format(_web_conf.get('domain'), _web_conf.get('port')))
    # app.rph.federation_entity.collector.web_cert_path = _cert
    app.run(host=_web_conf.get('domain'), port=_web_conf.get('port'),
            debug=_web_conf.get("debug"), ssl_context=context)
