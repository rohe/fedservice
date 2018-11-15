import json
import logging

from oidcservice.exception import ResponseError

from fedservice.entity_statement.statement import Statement

from fedservice.entity_statement.verify import flatten_metadata, \
    trust_path_expires_at
from fedservice.entity_statement.verify import verify_leaf_status
from fedservice.entity_statement.verify import verify_trust_chain


logger = logging.getLogger(__name__)


def eval_paths(node, key_jar, entity_type, flatten=True):
    """

    :param node: The starting point a Statement instance
    :param key_jar: A :py:class:`cryptojwt.key_jar.KeyJar` instance
    :param entity_type: Which type of metadata you want returned
    :returns: A dictionary with trust root entity IDs as keys and
        lists of Statement instances as values
    """
    trust_path = {}

    for path in node.paths():
        # Verify the trust chain
        path.reverse()
        ves = verify_trust_chain(path, key_jar)
        tp_exp = trust_path_expires_at(ves)
        try:
            leaf_ok = verify_leaf_status(ves)
        except ValueError as err:
            logger.warning(err)
        else:
            if not leaf_ok:
                continue

        if flatten:
            res = flatten_metadata(ves, entity_type, strict=False)
        else:
            # accept what's ever is in the statement provided by the OP
            res = Statement()
            res.le = ves[-1]

        iss_path = [x['iss'] for x in ves]
        iss_path.reverse()

        if res:
            res.exp = tp_exp
            res.iss_path = iss_path
            tr = ves[0]['iss']
            try:
                trust_path[tr].append(res)
            except KeyError:
                trust_path[tr] = [res]

    return trust_path


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
