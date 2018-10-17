import logging

from fedservice.entity_statement.verify import flatten_metadata
from fedservice.entity_statement.verify import verify_leaf_status
from fedservice.entity_statement.verify import verify_trust_chain


logger = logging.getLogger(__name__)


def eval_paths(node, key_jar, entity_type):
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
        try:
            leaf_ok = verify_leaf_status(ves)
        except ValueError as err:
            logger.warning(err)
        else:
            if not leaf_ok:
                continue

        res = flatten_metadata(ves, entity_type, strict=False)

        if res:
            tr = ves[0]['iss']
            try:
                trust_path[tr].append(res)
            except KeyError:
                trust_path[tr] = [res]

    return trust_path