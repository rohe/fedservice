import os

from flask.app import Flask
from oidcrp.configure import Configuration

from fedservice.rp import init_oidc_rp_handler

dir_path = os.path.dirname(os.path.realpath(__file__))


def oidc_provider_init_app(config_file, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    app.rp_config = Configuration.create_from_config_file(config_file)

    app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import oidc_rp_views
    except ImportError:
        from views import oidc_rp_views

    app.register_blueprint(oidc_rp_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.rph = init_oidc_rp_handler(app.rp_config, dir_path)

    return app
