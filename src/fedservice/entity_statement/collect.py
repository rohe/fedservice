import requests


class HTTPError(Exception):
    pass


class Issuer(object):
    def __init__(self, entity_statement):
        self.entity_statement = entity_statement
        self.superior = []


def get_entity_statement(entity_id, target, httpd, prefetch=False):
    """
    Fetches an entity statement from a metadata API endpoint according to
    section 4.2.1

    :param entity_id: The issuer of the signed information
    :param target: The subject about which the information is wanted
    :param httpd: A http client function used to fetch the information
    :param prefetch: If set to "true", it indicates that the requester would
        like the API to prefetch entity statements that may be relevant.
    :return: A signed JWT
    """
    url = '{}?target={}'.format(entity_id, target)
    res = httpd('GET', url)
    if res.status_code == 200:
        return res.txt
    else:
        raise HTTPError()


def collect_entity_statements(entity_statement, trusted_roots=None, seen=None,
                              httpd=None):
    """

    :param entity_statement: Entity statement to start with
    :param trusted_roots: Trust roots I know a trust
    :param seen:
    :param httpd:
    :return: A tree of entity statements
    """
    if not httpd:
        httpd = requests.request

    seen = seen or []
    node = Issuer(entity_statement)
    for authority, root in entity_statement['authorityHints'].items():
        if authority in seen:
            node.superior.append(seen[authority])
        else:
            if not trusted_roots or root in trusted_roots:
                try:
                    es = get_entity_statement(authority,
                                              target=entity_statement['iss'],
                                              httpd=httpd)
                except HTTPError:
                    pass
                else:
                    node.superior.append(
                        collect_entity_statements(es, trusted_roots, seen,
                                                  httpd))

    return node
