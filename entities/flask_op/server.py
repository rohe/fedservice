#!/usr/bin/env python3
import argparse
import json
import logging
import os
import ssl
import sys

import OpenSSL
import werkzeug
from oidcop.configure import Configuration

try:
    from .application import oidc_provider_init_app
except (ModuleNotFoundError, ImportError):
    from application import oidc_provider_init_app

dir_path = os.path.dirname(os.path.realpath(__file__))


logger = logging.getLogger(__name__)


class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    """
    We subclass this class so that we can gain access to the connection
    property. self.connection is the underlying client socket. When a TLS
    connection is established, the underlying socket is an instance of
    SSLSocket, which in turn exposes the getpeercert() method.

    The output from that method is what we want to make available elsewhere
    in the application.
    """

    def make_environ(self):
        """
        The superclass method develops the environ hash that eventually
        forms part of the Flask request object.

        We allow the superclass method to run first, then we insert the
        peer certificate into the hash. That exposes it to us later in
        the request variable that Flask provides
        """
        environ = super(PeerCertWSGIRequestHandler, self).make_environ()
        x509_binary = self.connection.getpeercert(True)
        if x509_binary:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
            environ['peercert'] = x509
        else:
            logger.warning('No peer certificate')
            environ['peercert'] = ''
        return environ


def main(config_file, args):
    logging.basicConfig(level=logging.DEBUG)
    config = Configuration.create_from_config_file(config_file)
    app = oidc_provider_init_app(config)

    web_conf = config.webserver

    kwargs = {}
    _cert = web_conf['cert'].format(dir_path)
    _key = web_conf['key'].format(dir_path)

    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)

    _verify_user = web_conf.get("verify_user")
    if _verify_user:
        if _verify_user == "required":
            context.verify_mode = ssl.CERT_REQUIRED
        elif _verify_user == "optional":
            context.verify_mode = ssl.CERT_OPTIONAL
        else:
            sys.exit("Unknown verify_user option. Details: {}".format(e))

        kwargs["request_handler"] = PeerCertWSGIRequestHandler

        _ca_bundle = app.config.get("cert_chain")
        if _ca_bundle:
            context.load_verify_locations(_ca_bundle)
    else:
        context.verify_mode = ssl.CERT_NONE

    try:
        context.load_cert_chain(_cert, _key)
    except Exception as e:
        sys.exit("Error starting flask server. Missing cert or key. Details: {}".format(e))

    if args.display:
        print(json.dumps(app.endpoint_context.provider_info, indent=4, sort_keys=True))
        exit(0)

    if args.insecure:
        app.endpoint_context.federation_entity.collector.insecure = True

    app.endpoint_context.federation_entity.collector.web_cert_path = web_conf['cert'].format(
        dir_path)

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
