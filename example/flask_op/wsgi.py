#!/usr/bin/env python3
import argparse
import json
import logging
import os

import OpenSSL
from fedservice.configure import FedOpConfiguration
from oidcop.configure import Configuration
from oidcop.utils import create_context
from oidcop.utils import lower_or_upper
from oidcrp.configure import create_from_config_file
import werkzeug

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


logging.basicConfig(level=logging.DEBUG)
config_file = "conf_uwsgi.yaml"
config = create_from_config_file(Configuration,
                                 entity_conf=[{'class': FedOpConfiguration, "attr": "op",
                                               "path": ["os", "server_info"]}],
                                 filename=config_file)
app = oidc_provider_init_app(config)

web_conf = config.webserver

# To be able to publish the TLS cert in the entity statement
_cert = os.path.join(dir_path, lower_or_upper(web_conf, "server_cert"))
app.server.endpoint_context.federation_entity.collector.web_cert_path = _cert


def main():
    global app

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='display', action='store_true')
    # parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()
    kwargs = {}

    if args.display:
        print(json.dumps(app.server.endpoint_context.provider_info, indent=4, sort_keys=True))
        exit(0)

    if args.insecure:
        app.server.endpoint_context.federation_entity.collector.insecure = True

    context = create_context(dir_path, web_conf)

    app.run(host=web_conf['domain'], port=web_conf['port'],
            debug=web_conf['debug'], ssl_context=context,
            **kwargs)


if __name__ == '__main__':
    main()
