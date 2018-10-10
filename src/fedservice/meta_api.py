import json
import logging
import os
from urllib.parse import urlparse

import cherrypy
from cryptojwt.key_jar import KeyJar
from cryptojwt.utils import as_bytes

from fedservice.entity_statement.create import create_entity_statement

logger = logging.getLogger(__name__)


class MetaAPI(object):
    def __init__(self, base_url, static_dir='static'):
        self.base_url = base_url
        self.static_dir = static_dir

    @cherrypy.expose
    def index(self):
        response = [
            '<html><head>',
            '<title>My metadata API endpoint</title>',
            '<link rel="stylesheet" type="text/css" href="/static/theme.css">'
            '</head><body>'
            "<h1>Welcome to my metadata API endpoint</h1>",
            '</body></html>'
        ]
        return '\n'.join(response)

    @cherrypy.expose
    def entity_statement(self, **kwargs):
        iss = kwargs['iss']

        try:
            sub = kwargs['sub']
        except KeyError:
            sub = iss

        _ip = urlparse(iss)
        _iss_dir = "{}".format(_ip.path[1:])
        if not os.path.isdir(_iss_dir):
            raise cherrypy.HTTPError(message='No such issuer')

        if iss != sub:
            _sp = urlparse(sub)
            _sub_dir = "{}/{}".format(_ip.path[1:], _sp.path[1:])

            if not os.path.isdir(_sub_dir):
                raise cherrypy.HTTPError(
                    message='Issuer do not sign for that entity')
        else:
            _sub_dir = _iss_dir

        metadata = json.loads(open(os.path.join(_sub_dir,
                                                'metadata.json')).read())
        key_jar = KeyJar()
        iss_jwks = open(os.path.join(_iss_dir, 'jwks.json')).read()
        key_jar.import_jwks_as_json(iss_jwks, iss)

        if iss != sub:
            sub_jwks = open(os.path.join(_sub_dir, 'jwks.json')).read()
            key_jar.import_jwks_as_json(sub_jwks, sub)

        roots_file = os.path.join(_sub_dir, 'roots.json')
        if os.path.isfile(roots_file):
            _roots = json.loads(open(roots_file).read())
            ahint = {}
            for key, val in _roots.items():
                vals = ["{}/{}".format(self.base_url, v) for v in val]
                ahint["{}/{}".format(self.base_url, key)] = vals
            args = {'authority_hints': ahint}
        else:
            args = {}

        jws = create_entity_statement(metadata, iss, sub, key_jar, **args)
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return as_bytes(json.dumps([jws]))

    def _cp_dispatch(self, vpath):
        # Only get here if vpath != None
        ent = cherrypy.request.remote.ip
        logger.info('ent:{}, vpath: {}'.format(ent, vpath))

        if vpath[0] in self.static_dir:
            return self
        elif len(vpath) == 2:
            a = vpath.pop(0)
            b = vpath.pop(0)
            if a == '.well-known' and b == 'openid-federation':
                return self.entity_statement

        return self
