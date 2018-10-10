#!/usr/bin/env python3
import cherrypy
import logging
import os

from fedservice.meta_api import MetaAPI

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
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-p', dest='port')
    parser.add_argument('-n', dest='netloc')
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
        base_url = "https://{}:{}".format(args.netloc, args.port)
    else:
        base_url = "http://{}:{}".format(args.netloc, args.port)

    cherrypy.tree.mount(MetaAPI(base_url), '/', provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = "certs/cert.pem"
        cherrypy.server.ssl_private_key = "certs/key.pem"

    cherrypy.engine.start()
    cherrypy.engine.block()
