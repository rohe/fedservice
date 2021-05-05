import os
from urllib.parse import urlparse

from flask.app import Flask
from oidcop.util import get_http_params

from fedservice.server import Server

folder = os.path.dirname(os.path.realpath(__file__))


def init_oidc_op(app):
    _op_config = app.srv_config.op

    _fed_conf = _op_config.federation
    _fed_conf.entity_id = _op_config.issuer # Works when openid_provider
    if 'httpc_params' not in _fed_conf:
        _fed_conf.httpc_params = get_http_params(_op_config.httpc_params)

    op = Server(_op_config, cwd=folder)

    for endp in op.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        if _vpath[0] == '':
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    return op


def oidc_provider_init_app(config, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    app.srv_config = config

    try:
        from .views import oidc_op_views
    except ImportError:
        from views import oidc_op_views

    app.register_blueprint(oidc_op_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.server = init_oidc_op(app)

    return app
