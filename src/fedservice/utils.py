import json
import logging
import ssl
import sys

from oidcservice.exception import ResponseError

logger = logging.getLogger(__name__)


def load_json(file_name):
    with open(file_name) as fp:
        js = json.load(fp)
    return js


def fed_parse_response(instance, info, sformat="", state="", **kwargs):
    if sformat in ['jose', 'jws', 'jwe']:
        resp = instance.post_parse_response(info, state=state)

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    else:
        return instance.parse_response(info, sformat, state, **kwargs)


def lower_or_upper(config, param, default=None):
    res = config.get(param.lower(), default)
    if not res:
        res = config.get(param.upper(), default)
    return res


def create_context(dir_path, config):
    _cert = "{}/{}".format(dir_path, lower_or_upper(config, "server_cert"))
    _key = "{}/{}".format(dir_path, lower_or_upper(config, "server_key"))

    context = ssl.SSLContext()  # PROTOCOL_TLS by default

    _verify_user = lower_or_upper(config, "verify_user")
    if _verify_user:
        context.verify_mode = ssl.CERT_REQUIRED
        _ca_bundle = lower_or_upper(config, "ca_bundle")
        if _ca_bundle:
            context.load_verify_locations(_ca_bundle)
    else:
        context.verify_mode = ssl.CERT_NONE

    try:
        context.load_cert_chain(_cert, _key)
    except Exception as e:
        sys.exit("Error starting flask server. Missing cert or key. Details: {}".format(e))

    return context


def get_http_params(config):
    params = {"verify": config.get('verify_ssl')}
    _cert = config.get('client_cert')
    _key = config.get('client_key')
    if _cert:
        if _key:
            params['cert'] = (_cert, _key)
        else:
            params['cert'] = _cert

    return params
