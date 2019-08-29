def create_authority_hints(default_hints, statements):
    """

    :param default_hints: The authority hints provided to the entity at startup
    :param statements: A list of Statement instances
    :return: An authority_hints dictionary
    """

    res = {}
    for sup, fos in default_hints.items():
        for statement in statements:
            if statement.fo in fos:
                try:
                    res[sup].append(statement.fo)
                except KeyError:
                    res[sup] = [statement.fo]

    return res
