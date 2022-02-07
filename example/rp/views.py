import logging
from time import localtime
from time import strftime

from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask.helpers import make_response
from flask.helpers import send_from_directory
import werkzeug

logger = logging.getLogger(__name__)

oidc_rp_views = Blueprint('oidc_rp', __name__, url_prefix='')


@oidc_rp_views.route('/static/<path:filename>')
def send_js(filename):
    return send_from_directory('static', filename)


@oidc_rp_views.route('/')
def index():
    _providers = current_app.srv_config.rp.clients.keys()
    return render_template('opbyuid.html', providers=_providers)


@oidc_rp_views.route('/irp')
def irp():
    return send_from_directory('entity_statements', 'irp.jws')


# @oidc_rp_views.route('/<string:op_hash>/.well-known/openid-federation')
@oidc_rp_views.route('/.well-known/openid-federation')
def wkof():
    _rph = current_app.rph
    if _rph.issuer2rp == {}:
        cli = _rph.init_client('dummy')
    else:
        # Any client will do
        cli = _rph.issuer2rp[list(_rph.issuer2rp.keys())[0]]

    _registration = cli.client_get("service", "registration")
    _jws = _registration.construct()

    response = make_response(_jws)
    response.headers['Content-Type'] = 'application/jose; charset=UTF-8'
    return response


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
        _providers = current_app.srv_config.rp.clients.keys()
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
            return make_response("Couldn't find client for {}".format(_iss), 400)

    return rp


def guess_rp(state):
    for _iss, _rp in current_app.rph.issuer2rp.items():
        _context = _rp.client_get("service_context")
        if _context.state.get_iss(request.args['state']):
            return _iss, _rp
    return None, None


@oidc_rp_views.route('/authz_cb')
def authz_cb():
    # This depends on https://datatracker.ietf.org/doc/draft-ietf-oauth-iss-auth-resp
    # being used
    _iss = request.args.get("iss")
    if _iss:
        rp = current_app.rph.issuer2rp[_iss]
        _context = rp.client_get("service_context")
        try:
            iss = _context.state.get_iss(request.args['state'])
        except KeyError:
            return make_response('Unknown state', 400)
    else:
        # This is unsecure
        rp, iss = guess_rp(request.args['state'])
        if rp is None:
            return make_response('No matching issuer', 400)
        _context = rp.client_get("service_context")

    if iss != _iss:
        return make_response(f"Wrong Issuer: {iss} != {request.args['iss']}", 400)

    logger.debug('Issuer: {}'.format(iss))
    try:
        res = current_app.rph.finalize(iss, request.args)
    except Exception as err:
        return make_response(f"{err}", 400)

    if 'userinfo' in res:
        endpoints = {}
        _pi = _context.get('provider_info')
        for k, v in _pi.items():
            if k.endswith('_endpoint'):
                endp = k.replace('_', ' ')
                endp = endp.capitalize()
                endpoints[endp] = v

        statement = _context.federation_entity.context.op_statements[0]
        _st = localtime(statement.exp)
        time_str = strftime('%a, %d %b %Y %H:%M:%S')
        return render_template('opresult.html', endpoints=endpoints,
                               userinfo=res['userinfo'],
                               access_token=res['token'],
                               federation=statement.anchor, fe_expires=time_str)
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
