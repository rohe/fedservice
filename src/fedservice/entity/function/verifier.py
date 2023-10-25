import logging
from typing import Callable
from typing import List

from cryptojwt import KeyBundle
from cryptojwt.exception import MissingKey
from cryptojwt.jws.jws import factory

from fedservice.entity.function import Function
from fedservice.entity_statement.constraints import meets_restrictions
from fedservice.entity_statement.statement import TrustChain

logger = logging.getLogger(__name__)


class TrustChainVerifier(Function):
    def __init__(self, upstream_get: Callable):
        Function.__init__(self, upstream_get)

    def trusted_anchor(self, entity_statement):
        _jwt = factory(entity_statement)
        payload = _jwt.jwt.payload()
        _keyjar = self.upstream_get("attribute", "keyjar")
        if payload['iss'] not in _keyjar:
            logger.warning(
                f"Trust chain ending in a trust anchor I do not know: {payload['iss']}", )
            return False

        return True

    def verify_trust_chain(self, entity_statement_list):
        """
        Verifies the trust chain. Works its way down from the Trust Anchor to the leaf.

        :param entity_statement_list: List of entity statements. The entity's self-signed statement last.
        :return: A sequence of verified entity statements
        """
        ves = []

        logger.debug("verify_trust_chain")
        if not self.trusted_anchor(entity_statement_list[0]):
            # Trust chain ending in a trust anchor I don't know.
            logger.debug("Unknown trust anchor")
            return ves

        n = len(entity_statement_list) - 1
        _keyjar = self.upstream_get("attribute", "keyjar")
        for entity_statement in entity_statement_list:
            _jwt = factory(entity_statement)
            if _jwt:
                logger.debug(f"JWS header: {_jwt.headers()}", )
                logger.debug(f"JWS payload: {_jwt.jwt.payload()}")
                keys = _keyjar.get_jwt_verify_keys(_jwt.jwt)
                if keys == []:
                    logger.error(f'No keys matching: {_jwt.jwt.headers}')
                    raise MissingKey(f'No keys matching: {_jwt.jwt.headers}')

                _key_spec = [f'{k.kty}:{k.use}:{k.kid}' for k in keys]
                logger.debug("Possible verification keys: %s", _key_spec)
                res = _jwt.verify_compact(keys=keys)
                logger.debug("Verified entity statement: %s", res)
                try:
                    _jwks = res['jwks']
                except KeyError:
                    if len(ves) != n:
                        raise ValueError('Missing signing JWKS')
                else:
                    _kb = KeyBundle(keys=_jwks['keys'])
                    try:
                        old = _keyjar.get_issuer_keys(res['sub'])
                    except KeyError:
                        _keyjar.add_kb(res['sub'], _kb)
                    else:
                        new = [k for k in _kb if k not in old]
                        if new:
                            _key_spec = [f'{k.kty}:{k.use}:{k.kid}' for k in new]
                            logger.debug(
                                "New keys added to the federation key jar for '{}': {}".format(
                                    res['sub'], _key_spec)
                            )
                            # Only add keys to the KeyJar if they are not already there.
                            _kb.set(new)
                            _keyjar.add_kb(res['sub'], _kb)

                ves.append(res)

        if ves and meets_restrictions(ves):
            return ves
        else:
            return []

    def trust_chain_expires_at(self, trust_chain):
        exp = -1
        for entity_statement in trust_chain:
            if exp >= 0:
                if entity_statement['exp'] < exp:
                    exp = entity_statement['exp']
            else:
                exp = entity_statement['exp']
        return exp

    def __call__(self, chain: List[str]):
        """

        :param chain: A chain of Entity Statements. The first one issued by a TA about an
            entity, the last an Entity Configuration.
        :returns: A TrustChain instances
        """
        logger.debug("Evaluate trust chain")
        verified_trust_chain = self.verify_trust_chain(chain)

        if not verified_trust_chain:
            return None

        _expires_at = self.trust_chain_expires_at(verified_trust_chain)

        trust_chain = TrustChain(exp=_expires_at, verified_chain=verified_trust_chain)

        iss_path = [x['iss'] for x in verified_trust_chain]
        trust_chain.anchor = iss_path[0]
        iss_path.reverse()
        trust_chain.iss_path = iss_path
        trust_chain.chain = chain

        return trust_chain
