from cryptojwt.jwt import JWT


def create_entity_statement(metadata, iss, sub, key_jar, authority_hints=None,
                            lifetime=86400, aud='', include_jwks=True,
                            **kwargs):
    """

    :param metadata: The entity's metadata organised as a dictionary with the
        entity type as key
    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param authority_hints: A dictionary with immediate superiors in the
        trust chains as keys and lists of identifier of trust roots as values.
    :param lifetime: The life time of the signed JWT.
    :param aud: Possible audience for the JWT
    :return: A signed JSON Web Token
    """

    msg = {"metadata": metadata, 'sub': sub}

    if authority_hints:
        msg['authority_hints'] = authority_hints

    if aud:
        msg['aud'] = aud

    if kwargs:
        msg.update(kwargs)

    if include_jwks:
        # The public signing keys of the subject
        msg['jwks'] = key_jar.export_jwks(issuer=sub)

    packer = JWT(key_jar=key_jar, iss=iss, lifetime=lifetime)

    return packer.pack(payload=msg)
