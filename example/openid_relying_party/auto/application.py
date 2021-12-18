import os

from flask.app import Flask
from oidcmsg.configure import Configuration
from oidcmsg.configure import create_from_config_file

from fedservice.configure import FedRPConfiguration
from fedservice.rp import init_oidc_rp_handler

dir_path = os.path.dirname(os.path.realpath(__file__))


def oidc_provider_init_app(config_file, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    app.srv_config = create_from_config_file(Configuration,
                                         entity_conf=[
                                             {"class": FedRPConfiguration,
                                              "attr": "rp"}],
                                         filename=config_file, base_path=dir_path)

    app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import oidc_rp_views
    except ImportError:
        from views import oidc_rp_views

    app.register_blueprint(oidc_rp_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.rph = init_oidc_rp_handler(app.srv_config.rp, dir_path)

    return app
