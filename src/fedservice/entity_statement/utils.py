def create_authority_hints(default_hints, statements):
    """

    :param default_hints: The authority hints provided to the entity at startup
    :param statements: A list of Statement instances
    :return: An authority_hints dictionary
    """

    intermediates = {statement.verified_chain[-1]['iss'] for statement in statements}
    return list(set(default_hints).intersection(intermediates))
