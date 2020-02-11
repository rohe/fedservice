import logging
import os
import ssl
import sys

import OpenSSL
import werkzeug

from fedservice.utils import create_context
from fedservice.utils import lower_or_upper

try:
    from . import application
except ImportError:
    import application

logger = logging.getLogger("")
LOGFILE_NAME = 'florp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')


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


if __name__ == "__main__":
    conf = sys.argv[1]
    name = 'oidc_rp'
    template_dir = os.path.join(dir_path, 'templates')
    app = application.oidc_provider_init_app(conf, name,
                                             template_folder=template_dir)

    _web_conf = app.config.get("webserver")
    context = create_context(dir_path, _web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))

    app.rph.federation_entity.collector.web_cert_path = _cert
    app.run(host='127.0.0.1', port=app.config.get('PORT'), debug=True, ssl_context=context,
            request_handler=PeerCertWSGIRequestHandler)
