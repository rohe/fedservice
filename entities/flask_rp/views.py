import logging
from time import localtime
from time import strftime

import werkzeug
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask.helpers import make_response
from flask.helpers import send_from_directory
from oidcservice.oidc.registration import Registration

logger = logging.getLogger(__name__)

oidc_rp_views = Blueprint('oidc_rp', __name__, url_prefix='')


@oidc_rp_views.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@oidc_rp_views.route('/')
def index():
    _providers = current_app.rp_config.clients.keys()
    return render_template('opbyuid.html', providers=_providers)


@oidc_rp_views.route('/irp')
def irp():
    return send_from_directory('entity_statements', 'irp.jws')


@oidc_rp_views.route('/.well-known/openid-federation')
def wkof():
    _rph = current_app.rph
    cli = _rph.init_client('')
    _asrv = cli.service['authorization']
    reg_srv= Registration(service_context=_asrv.service_context,
                             state_db=_asrv.state_db, conf= _asrv.conf)
    callbacks = _rph.create_callback()
    metadata = reg_srv.construct()
    _fe = current_app.rph.federation_entity
    iss = sub = _fe.entity_id
    _jws = _fe.create_entity_statement(
        {"openid_relying_party": metadata.to_dict()},
        iss, sub, authority_hints=_fe.authority_hints,
        lifetime=86400)

    return _jws


@oidc_rp_views.route('/rp')
def rp():
    try:
        iss = request.args['iss']
    except KeyError:
        link = ''
    else:
        link = iss

    try:
        uid = request.args['uid']
    except KeyError:
        uid = ''

    if link or uid:
        if uid:
            args = {'user_id': uid}
        else:
            args = {}

        try:
            result = current_app.rph.begin(link, **args)
        except Exception as err:
            return make_response('Something went wrong:{}'.format(err), 400)
        else:
            return redirect(result['url'], 303)
    else:
        _providers = current_app.rp_config.clients.keys()
        return render_template('opbyuid.html', providers=_providers)


def get_rp(op_hash):
    try:
        _iss = current_app.rph.hash2issuer[op_hash]
    except KeyError:
        logger.error('Unkown issuer: {} not among {}'.format(
            op_hash, list(current_app.rph.hash2issuer.keys())))
        return make_response("Unknown hash: {}".format(op_hash), 400)
    else:
        try:
            rp = current_app.rph.issuer2rp[_iss]
        except KeyError:
            return make_response("Couldn't find client for {}".format(_iss),
                                 400)

    return rp


@oidc_rp_views.route('/authz_cb/<op_hash>')
def authz_cb(op_hash):
    rp = get_rp(op_hash)

    try:
        iss = rp.session_interface.get_iss(request.args['state'])
    except KeyError:
        return make_response('Unknown state', 400)

    logger.debug('Issuer: {}'.format(iss))
    res = current_app.rph.finalize(iss, request.args)

    if 'userinfo' in res:
        endpoints = {}
        for k, v in rp.service_context.provider_info.items():
            if k.endswith('_endpoint'):
                endp = k.replace('_', ' ')
                endp = endp.capitalize()
                endpoints[endp] = v

        statement = rp.service_context.federation_entity.op_statements[0]
        _st = localtime(statement.exp)
        time_str = strftime('%a, %d %b %Y %H:%M:%S')
        return render_template('opresult.html', endpoints=endpoints,
                               userinfo=res['userinfo'],
                               access_token=res['token'],
                               federation=statement.fo, fe_expires=time_str)
    else:
        return make_response(res['error'], 400)


@oidc_rp_views.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@oidc_rp_views.route('/repost_fragment')
def repost_fragment():
    return 'repost_fragment'


@oidc_rp_views.route('/ihf_cb')
def ihf_cb(self, op_hash='', **kwargs):
    logger.debug('implicit_hybrid_flow kwargs: {}'.format(kwargs))
    return render_template('repost_fragment.html')
