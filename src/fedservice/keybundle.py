import json
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt import key_bundle
from cryptojwt.key_jar import KeyJar

logger = logging.getLogger(__name__)


class KeyBundle(key_bundle.KeyBundle):
    """
    Extended :py:class:`oidcmsg.key_bundle.KeyBundle` class that supports
    signed JWKS uris.
    """

    def __init__(self,
                 keys: Union[List, Dict] = None,
                 source: Optional[str] = "",
                 cache_time: Optional[int] = 300,
                 file_format: Optional[str] = "jwk",
                 keytype: Optional[str] = "RSA",
                 keyusage: Optional[Union[List[str], str]] = None,
                 federation_keys: Optional[Union[str, KeyJar]] = None):
        super(KeyBundle, self).__init__(keys=keys, source=source,
                                        cache_time=cache_time,
                                        fileformat=file_format,
                                        keytype=keytype, keyusage=keyusage)
        if federation_keys is not None:
            if isinstance(federation_keys, KeyJar):
                self.federation_keys = federation_keys
            else:
                self.federation_keys = KeyJar()
                self.federation_keys.import_jwks(federation_keys, '')

    def _parse_remote_response(self, response):
        """
        Parse simple JWKS or signed JWKS from the HTTP response.

        :param response: HTTP response from the 'jwks_uri' or 'signed_jwks_uri'
            endpoint
        :return: response parsed as JSON or None
        """
        # Check if the content type is the right one.
        try:
            if response.headers["Content-Type"] == 'application/json':
                logger.debug(
                    "Loaded JWKS: %s from %s" % (response.text, self.source))
                try:
                    return json.loads(response.text)
                except ValueError:
                    return None
            elif response.headers["Content-Type"] == 'application/jwt':
                logger.debug(
                    "Signed JWKS: %s from %s" % (response.text, self.source))
                _jwt = JWT(key_jar=self.federation_keys)
                _resp = _jwt.unpack(response.text)
                return _resp
            else:
                logger.error('Wrong content type: {}'.format(
                    response.headers['Content-Type']))
                raise ValueError('Content-type mismatch')
        except KeyError:
            pass

    def signed_jwks(self, issuer, sign_alg: Optional[str] = "RS256"):
        """

        :return: Signed JWT containing a JWKS
        """
        jwks = json.loads(self.jwks())
        _jwt = JWT(self.federation_keys, iss=issuer, sign_alg=sign_alg)
        return _jwt.pack(jwks)
