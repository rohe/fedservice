#!/usr/bin/env python3
import cherrypy
import logging
import os

from cryptojwt.key_jar import init_key_jar

from fedservice.meta_api import MetaAPIDb

logger = logging.getLogger("")
LOGFILE_NAME = 'farp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', dest='authn_info')
    parser.add_argument('-d', dest='db_url')
    parser.add_argument('-n', dest='netloc')
    parser.add_argument('-p', dest='port')
    parser.add_argument('-s', dest='sign_alg')
    parser.add_argument('-t', dest='tls', action='store_true')
    args = parser.parse_args()

    folder = os.path.abspath(os.curdir)
    _port = int(args.port)

    cherrypy.config.update(
        {'environment': 'production',
         'log.error_file': 'error.log',
         'log.access_file': 'access.log',
         'tools.trailing_slash.on': False,
         'server.socket_host': '0.0.0.0',
         'log.screen': True,
         'tools.sessions.on': True,
         'tools.encode.on': True,
         'tools.encode.encoding': 'utf-8',
         'server.socket_port': _port
         })

    provider_config = {
        '/': {
            'root_path': 'localhost',
            'log.screen': True
        },
        '/static': {
            'tools.staticdir.dir': os.path.join(folder, 'static'),
            'tools.staticdir.debug': True,
            'tools.staticdir.on': True,
            'tools.staticdir.content_types': {
                'json': 'application/json',
                'jwks': 'application/json',
                'jose': 'application/jose'
            },
            'log.screen': True,
            'cors.expose_public.on': True
        }}

    if args.tls:
        issuer = "https://{}:{}".format(args.netloc, args.port)
    else:
        issuer = "http://{}:{}".format(args.netloc, args.port)

    KEYSPEC = [
        {"type": "RSA", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
        ]
    key_jar = init_key_jar(private_path='priv_keys.json', key_defs=KEYSPEC,
                           owner=issuer)

    user, pw = args.authn_info.split(':')
    au = {'user': user, 'password':pw}

    cherrypy.tree.mount(MetaAPIDb(authn_info=au, db_uri=args.db_url,
                                  key_jar=key_jar, sign_alg=args.sign_alg,
                                  issuer=issuer),
                        '/',
                        provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = "certs/cert.pem"
        cherrypy.server.ssl_private_key = "certs/key.pem"

    cherrypy.engine.start()
    cherrypy.engine.block()
