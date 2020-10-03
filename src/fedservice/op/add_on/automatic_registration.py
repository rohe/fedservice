from oidcendpoint.client_authn import PrivateKeyJWT
from oidcendpoint.client_authn import RequestParam

from fedservice.op import registration


def add_support(endpoint, **kwargs):
    """

    :param endpoint:
    :param kwargs:
    :return:
    """
    for endp in kwargs.get('where', []):  # ["authorization", "pushed_authorization"]
        auth_endpoint = endpoint.get(endp)

        if auth_endpoint is None and endp == 'authorization':
            auth_endpoint = endpoint.get('federation_{}'.format(endp))

        if auth_endpoint:
            auto_reg = registration.Registration(auth_endpoint.endpoint_context, **kwargs)
            auth_endpoint.automatic_registration_endpoint = auto_reg

            if endp == 'authorization':
                if not auth_endpoint.client_authn_method:
                    auth_endpoint.client_authn_method = [
                        RequestParam(auth_endpoint.endpoint_context)]
            else:  # pushed_authorization
                if not auth_endpoint.client_authn_method:
                    auth_endpoint.client_authn_method = [
                        PrivateKeyJWT(auth_endpoint.endpoint_context)]

            _pi = auth_endpoint.endpoint_context.provider_info
            _supported = kwargs.get('client_registration_authn_methods_supported')
            if _supported:
                _pi['client_registration_authn_methods_supported'] = _supported
            # else:
            #     _pi['client_registration_authn_methods_supported'] = [
            #         _method.tag for _method in auth_endpoint.client_authn_method]
