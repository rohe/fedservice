from flask import Blueprint
from flask import current_app
from flask import send_from_directory

sigserv_views = Blueprint("sig_serv", __name__, url_prefix='')


@sigserv_views.route("/static/<path:path>")
def send_js(path):
    return send_from_directory('static', path)


@sigserv_views.route("/eid/<unit>/.well-known/openid-federation")
def well_known(unit):
    _srv = current_app.signing_service.issuer[unit]
    return _srv.create_entity_statement(unit)


@sigserv_views.route("/api/<unit>")
def signer(unit):
    _srv = current_app.signing_service.issuer[unit]
    return _srv.create_entity_statement(unit)
