import cherrypy
import json
import logging
import os

from cryptojwt.utils import as_bytes

from fedservice.metadata_api.db import db_make_entity_statement
from fedservice.metadata_api.fs import make_entity_statement
from fedservice.metadata_api.fs import mk_path

logger = logging.getLogger(__name__)


class MetaAPI(object):
    def __init__(self, static_dir='static'):
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
    def resolve_metadata(self, **kwargs):
        """
        Evaluate a trust path of another entity
        TODO implement

        :param kwargs:
        :return:
        """
        return "OK"

    @cherrypy.expose
    def listing(self, **kwargs):
        raise NotImplementedError()

    def entity_statement(self, **kwargs):
        raise NotImplementedError()

    @cherrypy.expose
    def metadata_api(self, **kwargs):
        try:
            _op = kwargs['op']
        except KeyError:
            _op = "fetch"

        if _op == 'fetch':
            return self.entity_statement(**kwargs)
        elif _op == 'resolve_metadata':
            return self.resolve_metadata(**kwargs)
        elif _op == 'listing':
            return self.listing(**kwargs)
        else:
            raise cherrypy.HTTPError(400, "Unknown operation")

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
                return self.metadata_api

        return self


class MetaAPIFS(MetaAPI):
    def __init__(self, base_url, data_dir='.', static_dir='static'):
        MetaAPI.__init__(self, static_dir)
        self.base_url = base_url
        self.data_dir = data_dir

    @cherrypy.expose
    def entity_statement(self, **kwargs):
        jws = make_entity_statement(self.base_url, self.data_dir, **kwargs)
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return as_bytes(json.dumps(jws))

    @cherrypy.expose
    def listing(self, **kwargs):
        """
        List the subordinates of this intermediate
        TODO implement

        :param kwargs:
        :return:
        """
        try:
            iss = kwargs['iss']
        except KeyError:
            raise cherrypy.HTTPError(400, 'Missing required argument')

        _iss_dir = mk_path(self.data_dir, iss)
        if not os.path.isdir(_iss_dir):
            raise cherrypy.HTTPError(message='No such issuer')

        return "OK"


class MetaAPIDb(MetaAPI):
    def __init__(self, authn_info, db_uri, key_jar, issuer, static_dir='static',
                 lifetime=14400, sign_alg='ES256'):
        MetaAPI.__init__(self, static_dir)
        self.authn_info = authn_info
        self.db_uri = db_uri
        self.key_jar = key_jar
        self.issuer = issuer
        self.lifetime = lifetime
        self.sign_alg = sign_alg

    @cherrypy.expose
    def entity_statement(self, **kwargs):
        if 'iss' in kwargs:
            if kwargs['iss'] != self.issuer:
                raise cherrypy.HTTPError(
                    403, 'Not prepared to sign as "{}"'.format(kwargs['iss']))
        else:
            kwargs['iss'] = self.issuer

        jws = db_make_entity_statement(self.db_uri, key_jar=self.key_jar,
                                       lifetime=self.lifetime,
                                       sign_lag=self.sign_alg,
                                       authn_info=self.authn_info, **kwargs)
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return as_bytes(json.dumps(jws))
