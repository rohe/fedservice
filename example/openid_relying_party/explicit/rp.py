#!/usr/bin/env python3
import os
import sys

from oidcrp.util import create_context
from oidcrp.util import lower_or_upper

try:
    from . import application
except ImportError:
    import application

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')

if __name__ == "__main__":
    conf = sys.argv[1]
    name = 'oidc_rp'
    template_dir = os.path.join(dir_path, 'templates')
    app = application.oidc_provider_init_app(conf, name, template_folder=template_dir)
    _web_conf = app.srv_config.web_conf
    context = create_context(dir_path, _web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))

    print('Listening on {}:{}'.format(_web_conf.get('domain'), _web_conf.get('port')))
    # app.rph.federation_entity.collector.web_cert_path = _cert
    app.run(host=_web_conf.get('domain'), port=_web_conf.get('port'),
            debug=_web_conf.get("debug"), ssl_context=context)
