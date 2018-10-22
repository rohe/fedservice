def create_authority_hints(default_hints, paths):
    """

    :param default_hints: The authority hints provided to the entity at startup
    :param paths: The response from an eval call
    :return: An authority_hints dictionary
    """

    res = {}
    for sup, fos in default_hints.items():
        for fo, statem in paths.items():
            if fo in fos:
                try:
                    res[sup].append(fo)
                except KeyError:
                    res[sup] = [fo]

    return res
