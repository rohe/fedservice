from flask import Blueprint
from flask import current_app
from flask import make_response
from flask import request
from flask import send_from_directory

from fedservice.exception import UnknownEntity

sigserv_views = Blueprint("sig_serv", __name__, url_prefix='')


@sigserv_views.route("/static/<path:path>")
def send_js(path):
    return send_from_directory('static', path)


@sigserv_views.route("/eid/<eid>/.well-known/openid-federation")
def well_known(eid):
    # self signed entity statement
    response = make_response(current_app.signing_service.issuer.create_entity_statement(eid))
    response.headers['Content-Type'] = 'application/jose; charset=UTF-8'
    return response


@sigserv_views.route("/api/<eid>")
def signer(eid):
    args = [eid]
    _srv = current_app.signing_service.issuer
    if "sub" in request.args:
        args.append(request.args["sub"])

    try:
        info = _srv.create_entity_statement(*args)
    except UnknownEntity as err:
        make_response(400, "Unknown entity")
    else:
        if info:
            response = make_response(info)
            response.headers['Content-Type'] = 'application/jose; charset=UTF-8'
            return response
        else:
            make_response(400, f"No information on {args[:-1]}")
