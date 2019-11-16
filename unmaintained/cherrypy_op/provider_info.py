#!/usr/bin/env python3
import importlib
import os
import sys

from fedoidcendpoint.endpoint_context import EndpointContext
from oidcmsg.key_jar import init_key_jar
from oidcop.cherrypy import OpenIDProvider

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(dest="config")
    args = parser.parse_args()

    folder = os.path.abspath(os.curdir)
    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)

    _provider_config = config.CONFIG['provider']
    _server_info_config = config.CONFIG['server_info']
    _jwks_config = _server_info_config['jwks']

    _kj = init_key_jar(private_path=_jwks_config['private_path'],
                       key_defs=_provider_config['key_defs'],
                       public_path=_jwks_config['local_path'])

    endpoint_context = EndpointContext(config.CONFIG['server_info'], keyjar=_kj,
                                       cwd=folder)

    op = OpenIDProvider(config, endpoint_context)

    pi_endpoint = op.endpoint_context.endpoint['provider_info']
    _conf = pi_endpoint.provider_info_with_signing_keys()
    fp = open('provider_info.json', 'w')
    fp.write(_conf.to_json())
    fp.close()
