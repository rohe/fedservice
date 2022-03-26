#!/usr/bin/env python3
import os
import sys

from flask.app import Flask
from idpyoidc.configure import Configuration
from idpyoidc.configure import create_from_config_file
from idpyoidc.client.util import create_context
from idpyoidc.client.util import lower_or_upper

from fedservice.configure import FedEntityConfiguration
from fedservice.entity import FederationEntity

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')

def init_entity(config, cwd):
    return FederationEntity(config=config, cwd=cwd)


def init_app(config_file, name=None, **kwargs) -> Flask:
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    app.srv_config = create_from_config_file(Configuration,
                                             entity_conf=[
                                                 {"class": FedEntityConfiguration,
                                                  "attr": "federation",
                                                  "path": ["federation"]
                                                  }],
                                             filename=config_file, base_path=dir_path)

    # app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import intermediate
    except ImportError:
        from views import intermediate

    app.register_blueprint(intermediate)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.server = init_entity(app.srv_config.federation, dir_path)

    return app


if __name__ == "__main__":
    print(sys.argv)
    name = sys.argv[1]
    conf = sys.argv[2]
    template_dir = os.path.join(dir_path, 'templates')
    app = init_app(conf, name, template_folder=template_dir)
    _web_conf = app.srv_config.web_conf
    context = create_context(dir_path, _web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))

    print('Listening on {}:{}'.format(_web_conf.get('domain'), _web_conf.get('port')))
    # app.rph.federation_entity.collector.web_cert_path = _cert
    app.run(host=_web_conf.get('domain'), port=_web_conf.get('port'),
            debug=_web_conf.get("debug"), ssl_context=context)
