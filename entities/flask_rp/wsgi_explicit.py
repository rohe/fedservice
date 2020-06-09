#!/usr/bin/env python3
import os
import sys

import OpenSSL
import werkzeug
from oidcrp.util import create_context
from oidcrp.util import lower_or_upper

try:
    from . import application
except ImportError:
    import application


dir_path = os.path.dirname(os.path.realpath(__file__))


def main():
    global app
    _web_conf = app.rp_config.web_conf
    context = create_context(dir_path, _web_conf)
    app.run(host=app.rp_config.domain, port=app.rp_config.port,
            debug=_web_conf.get("debug"), ssl_context=context)


conf = "conf_fed_expl_pers.yaml"
name = 'rp_explicit'
template_dir = os.path.join(dir_path, 'templates')
app = application.oidc_provider_init_app(conf, name, template_folder=template_dir)
# _web_conf = app.rp_config.web_conf
# _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))
# app.rph.federation_entity.collector.web_cert_path = _cert

if __name__ == "__main__":
    main()