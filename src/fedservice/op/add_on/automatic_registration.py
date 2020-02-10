from oidcendpoint.oidc import registration


def add_automatic_registration_support(endpoint, **kwargs):
    """

    :param endpoint:
    :param kwargs:
    :return:
    """
    for endp in ["authorization", "pushed_authorization"]:
        auth_endpoint = endpoint.get(endp)
        if auth_endpoint:
            auto_reg = registration.Registration(auth_endpoint.endpoint_context, **kwargs)
            auth_endpoint.automatic_registration_endpoint = auto_reg

            # if auth_endpoint.client_authn_method:
            #     if "private_key_jwt" not in auth_endpoint.client_authn_method:
            #         auth_endpoint.client_authn_method.append("private_key_jwt")
            # else:
            #     auth_endpoint.client_authn_method = ['private_key_jwt']
