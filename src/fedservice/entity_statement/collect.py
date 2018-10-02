import json
from urllib.parse import urlencode

import requests
from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory


class HTTPError(Exception):
    pass


class Issuer(object):
    def __init__(self, entity_statement):
        self.entity_statement = entity_statement
        self.superior = []

    def paths(self):
        res = []
        if not self.superior:
            return [[self.entity_statement]]
        else:
            for sup in self.superior:
                for p in sup.paths():
                    l = [self.entity_statement]
                    l.extend(p)
                    res.append(l)
            return res


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
    url = '{}?{}'.format(entity_id, urlencode({'target': target}))
    res = httpd('GET', url)
    if res.status_code == 200:
        return res.text
    else:
        raise HTTPError()


def load_entity_statement(node, target, authority, trusted_roots, seen, httpd):
    try:
        _jws = get_entity_statement(authority, target=target, httpd=httpd)
    except HTTPError:
        pass
    else:
        _jwt = factory(_jws)
        if _jwt:
            es = json.loads(as_unicode(_jwt.jwt.part[1]))
            node.superior.append(
                collect_entity_statements(es, trusted_roots, seen, httpd))
    return node


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
    if 'authority_hints' not in entity_statement:
        return node

    for authority, roots in entity_statement['authority_hints'].items():
        if authority in seen:
            node.superior.append(seen[authority])
        else:
            if trusted_roots:
                for root in roots:
                    if root in trusted_roots:
                        load_entity_statement(node, entity_statement['iss'],
                                              authority, trusted_roots, seen,
                                              httpd)
            else:
                load_entity_statement(node, entity_statement['iss'],
                                      authority, trusted_roots, seen,
                                      httpd)

    return node
