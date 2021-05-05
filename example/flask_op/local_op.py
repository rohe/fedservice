#!/usr/bin/env python3
import argparse
import json
import logging
import os

# import OpenSSL
# import werkzeug
from oidcop.configure import create_from_config_file
from oidcop.utils import create_context
from oidcop.utils import lower_or_upper

from fedservice.configure import Configuration

try:
    from .application import oidc_provider_init_app
except (ModuleNotFoundError, ImportError):
    from application import oidc_provider_init_app

dir_path = os.path.dirname(os.path.realpath(__file__))

logger = logging.getLogger(__name__)


def main(config_file, args):
    logging.basicConfig(level=logging.DEBUG)
    config = create_from_config_file(Configuration, config_file)
    app = oidc_provider_init_app(config)

    web_conf = config.webserver

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
    parser.add_argument(dest="config")
    args = parser.parse_args()
    main(args.config, args)
