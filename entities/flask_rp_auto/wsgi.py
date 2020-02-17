import logging
import os
import sys

from oidcrp.util import create_context
from oidcrp.util import lower_or_upper

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
logging.basicConfig(level=logging.DEBUG)


if __name__ == "__main__":
    dir_path = os.path.dirname(os.path.realpath(__file__))
    conf = sys.argv[1]
    name = 'oidc_auto_rp'
    template_dir = os.path.join(dir_path, 'templates')
    app = application.oidc_provider_init_app(conf, name,
                                             template_folder=template_dir)

    _web_conf = app.config.get("webserver")
    context = create_context(dir_path, _web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))

    app.rph.federation_entity.collector.web_cert_path = _cert
    app.run(host=_web_conf.get('domain'), port=_web_conf.get('port'), debug=True,
            ssl_context=context)

