import logging

from cryptojwt.jwt import JWT

logger = logging.getLogger(__name__)


def create_entity_statement(iss, sub, key_jar, metadata=None, metadata_policy=None,
                            authority_hints=None, lifetime=86400, aud='', include_jwks=True,
                            constraints=None, **kwargs):
    """

    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param metadata: The entity's metadata organised as a dictionary with the
        entity type as key
    :param metadata_policy: Metadata policy
    :param authority_hints: A dictionary with immediate superiors in the
        trust chains as keys and lists of identifier of trust roots as values.
    :param lifetime: The life time of the signed JWT.
    :param aud: Possible audience for the JWT
    :param include_jwks: Add JWKS
    :param constraints: A dictionary with constraints.
    :return: A signed JSON Web Token
    """

    msg = {'sub': sub}
    if metadata:
        msg['metadata'] = metadata

    if metadata_policy:
        msg['metadata_policy'] = metadata_policy

    if authority_hints:
        msg['authority_hints'] = authority_hints

    if aud:
        msg['aud'] = aud

    if constraints:
        msg['constraints'] = constraints

    if kwargs:
        msg.update(kwargs)

    if include_jwks:
        # The public signing keys of the subject
        msg['jwks'] = key_jar.export_jwks(issuer=sub)

    packer = JWT(key_jar=key_jar, iss=iss, lifetime=lifetime)

    return packer.pack(payload=msg)
