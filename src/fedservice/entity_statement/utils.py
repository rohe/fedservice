def create_authority_hints(trust_chains):
    """

    :param default_hints: The authority hints provided to the entity at startup
    :param trust_chains: A list of TrustChain instances
    :return: An authority_hints dictionary
    """

    return {trust_chain.iss_path[0] for trust_chain in trust_chains if len(trust_chain.iss_path)}
