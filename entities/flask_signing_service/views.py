from urllib.parse import quote_plus
from urllib.parse import urlparse

from flask import Blueprint
from flask import current_app
from flask import send_from_directory
from flask import request

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
    _sub_url = request.args["sub"]
    pf_part = urlparse(_srv.url_prefix)
    part = urlparse(_sub_url)
    if pf_part.scheme == part.scheme:
        if pf_part.netloc == part.netloc:
            return _srv.create_entity_statement(part.path.split('/')[-1])

    return _srv.create_entity_statement(quote_plus(_sub_url))
