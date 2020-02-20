import os

from cryptojwt.key_jar import init_key_jar
from flask.app import Flask
from oidcrp.configure import Configuration
from oidcrp.util import get_http_params

from fedservice import create_federation_entity
from fedservice.rp import RPHandler

dir_path = os.path.dirname(os.path.realpath(__file__))


def init_oidc_rp_handler(app):
    rp_keys_conf = app.rp_config.rp_keys
    _fed_conf = app.rp_config.federation

    _httpc_params = app.rp_config.httpc_params

    _kj_args = {k: v for k, v in rp_keys_conf.items() if k != 'uri_path'}
    _kj = init_key_jar(**_kj_args)
    _kj.import_jwks_as_json(_kj.export_jwks_as_json(True, ''), _fed_conf['entity_id'])
    _kj.httpc_params = _httpc_params

    _fed_conf['entity_id'] = _fed_conf['entity_id'].format(domain=app.rp_config.domain,
                                                           port=app.rp_config.port)
    federation_entity = create_federation_entity(httpc_params=_httpc_params, **_fed_conf)
    federation_entity.key_jar.httpc_params = _httpc_params

    _path = rp_keys_conf['uri_path']
    if _path.startswith('./'):
        _path = _path[2:]
    elif _path.startswith('/'):
        _path = _path[1:]

    rph = RPHandler(base_url=app.rp_config.base_url, hash_seed=app.rp_config.hash_seed,
                    keyjar=_kj, jwks_path=_path,
                    client_configs=app.rp_config.clients,
                    services=app.rp_config.services, httpc_params=_httpc_params,
                    federation_entity=federation_entity)

    return rph


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
    app.rph = init_oidc_rp_handler(app)

    return app
