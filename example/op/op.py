#!/usr/bin/env python3
import argparse
import json
import logging
import os
# import OpenSSL
# import werkzeug
from urllib.parse import urlparse

from flask import Flask
from oidcmsg.configure import Configuration
from oidcmsg.configure import create_from_config_file
from oidcop.util import get_http_params
from oidcop.utils import create_context
from oidcop.utils import lower_or_upper

from fedservice.configure import DEFAULT_FED_FILE_ATTRIBUTE_NAMES
from fedservice.configure import FedOpConfiguration
from fedservice.op import FederationServer

dir_path = os.path.dirname(os.path.realpath(__file__))

logger = logging.getLogger(__name__)


def init_oidc_op(app: Flask):
    _op_config = app.srv_config.op

    _fed_conf = _op_config.federation
    if 'httpc_params' not in _fed_conf:
        _fed_conf.httpc_params = get_http_params(_op_config.httpc_params)

    op = FederationServer(_op_config, cwd=dir_path)

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


def main(config_file, args):
    logging.basicConfig(level=logging.DEBUG)
    config = create_from_config_file(Configuration,
                                     entity_conf=[{
                                         "class": FedOpConfiguration,
                                         "attr": "op",
                                         "path": ["op", "server_info"]
                                     }],
                                     file_attributes=DEFAULT_FED_FILE_ATTRIBUTE_NAMES,
                                     filename=config_file)
    app = oidc_provider_init_app(config, name=args.name)

    web_conf = config.web_conf

    context = create_context(dir_path, web_conf)

    kwargs = {}

    _srv_context = app.server.server_get("endpoint_context")

    if args.display:
        print(json.dumps(_srv_context.provider_info, indent=4, sort_keys=True))
        exit(0)

    if args.insecure:
        _srv_context.federation_entity.collector.insecure = True

    _cert = os.path.join(dir_path, lower_or_upper(web_conf, "server_cert"))
    _srv_context.federation_entity.collector.web_cert_path = _cert

    app.run(host=web_conf['domain'], port=web_conf['port'],
            debug=web_conf['debug'], ssl_context=context,
            **kwargs)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='display', action='store_true')
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="name")
    parser.add_argument(dest="config")
    args = parser.parse_args()
    main(args.config, args)
