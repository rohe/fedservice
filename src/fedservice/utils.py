import json
import logging

from oidcservice.exception import ResponseError

logger = logging.getLogger(__name__)


def load_json(file_name):
    with open(file_name) as fp:
        js = json.load(fp)
    return js


def fed_parse_response(instance, info, sformat="", state="", **kwargs):
    if sformat in ['jose','jws','jwe']:
        resp = instance.post_parse_response(info, state=state)

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    else:
        return instance.parse_response(info, sformat, state, **kwargs)
