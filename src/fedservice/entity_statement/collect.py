import json
from urllib.parse import urlencode

import requests
from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory

REL = 'http://oauth.net/specs/federation/1.0/entity'


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


class Collector(object):
    def __init__(self, httpd=None, web_finger=None, trusted_roots=None):
        self.seen = []
        self.httpd = httpd or requests.request
        self.web_finger = web_finger
        self.trusted_roots = trusted_roots

    def get_entity_statement(self, entity_id, target, prefetch=False):
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
        res = self.httpd('GET', url)
        if res.status_code == 200:
            return res.text
        else:
            raise HTTPError(res.text)

    def load_entity_statement(self, iss, sub):
        """

        :param iss: The issuer of the statement
        :param sub: The entity the statement describes
        :param httpd: A HTTP client function to use
        :param web_finger: WebFinger instance
        :return: An unverified entity statement
        """

        metadata_api_endpoint = ''
        # Use web finger to find the metadata API
        if self.web_finger:
            _url = self.web_finger.query(iss)
            hres = self.httpd('GET', _url)
            res = self.web_finger.parse_response(hres.text)
            if res['subject'] == iss:
                for link in res['links']:
                    if link['rel'] == REL:
                        metadata_api_endpoint = link['href']
                        break
        else:
            metadata_api_endpoint = iss

        if not metadata_api_endpoint:
            raise ValueError('No Metadata API endpoint')

        try:
            _jws = self.get_entity_statement(metadata_api_endpoint, target=sub)
        except HTTPError as err:
            raise
        else:
            _jwt = factory(_jws)
            if _jwt:
                return json.loads(as_unicode(_jwt.jwt.part[1]))

        return None

    def follow_path(self, iss, sub):
        """
        Unravel a branch

        :param iss:
        :param sub:
        :param trusted_roots:
        :param seen:
        :param httpd:
        :param web_finger:
        :return:
        """
        _es = self.load_entity_statement(iss, sub)
        if _es:
            return self.collect_entity_statements(_es)

    def collect_entity_statements(self, entity_statement):
        """
        Collect information from the immediate superiors

        :param entity_statement: Entity Statement
        :param trusted_roots: Trust roots I know a trust
        :param seen: List of entity ID'n I've seen and collected information about
        :param httpd: A HTTP client function
        :param web_finger: WebFinger instance
        :return: A tree of entity statements
        """

        node = Issuer(entity_statement)
        if 'authority_hints' not in entity_statement:
            return node

        for authority, roots in entity_statement['authority_hints'].items():
            if authority in self.seen:
                node.superior.append(self.seen[authority])
            else:
                if self.trusted_roots:
                    for root in roots:
                        if root in self.trusted_roots:
                            _node = self.follow_path(authority,
                                                     entity_statement['iss'])
                            if _node:
                                node.superior.append(_node)
                            break
                else:
                    _node = self.follow_path(authority, entity_statement['iss'])
                    if _node:
                        node.superior.append(_node)

        return node
