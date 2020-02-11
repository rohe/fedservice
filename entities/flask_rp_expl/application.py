import os

from oidcservice.util import load_yaml_config

from fedservice.rp import RPHandler

from fedservice import create_federation_entity
from flask.app import Flask

from cryptojwt.key_jar import init_key_jar

dir_path = os.path.dirname(os.path.realpath(__file__))


def init_oidc_rp_handler(app):
    oidc_keys_conf = app.config.get('RP_KEYS')
    _fed_conf = app.config['CLIENT_CONFIG'].get('federation')

    verify_ssl = app.config.get('VERIFY_SSL')
    http_args = {"verify": verify_ssl}

    _kj_args = {k: v for k, v in oidc_keys_conf.items() if k != 'public_path'}
    _kj = init_key_jar(**_kj_args)

    _kj.import_jwks_as_json(_kj.export_jwks_as_json(True, ''),
                            _fed_conf['entity_id'])
    _kj.httpc_params = http_args

    federation_entity = create_federation_entity(http_args=http_args, **_fed_conf)
    federation_entity.key_jar.httpc_params = http_args

    _path = oidc_keys_conf['public_path']
    if _path.startswith('./'):
        _path = _path[2:]
    elif _path.startswith('/'):
        _path = _path[1:]

    rph = RPHandler(base_url=app.config.get('BASEURL'), hash_seed="BabyHoldOn",
                    keyjar=_kj, jwks_path=_path,
                    client_configs=app.config.get('clients'),
                    services=app.config.get('SERVICES'), http_args=http_args,
                    federation_entity=federation_entity)

    return rph


def oidc_provider_init_app(config_file, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    if config_file.endswith('.yml'):
        app.config.update(load_yaml_config(config_file))
    elif config_file.endswith('.py'):
        app.config.from_pyfile(os.path.join(dir_path, config_file))
    else:
        raise ValueError('Unknown configuration format')

    app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import oidc_rp_views
    except ImportError:
        from views import oidc_rp_views

    app.register_blueprint(oidc_rp_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.rph = init_oidc_rp_handler(app)

    return app
