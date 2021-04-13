from oidcop.client_authn import PrivateKeyJWT
from oidcop.client_authn import RequestParam

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
            _context = auth_endpoint.server_get("endpoint_context")
            auto_reg = registration.Registration(auth_endpoint.server_get, **kwargs)
            auth_endpoint.automatic_registration_endpoint = auto_reg

            if endp == 'authorization':
                if isinstance(auth_endpoint.client_verification_method, list):
                    auth_endpoint.client_verification_method.append(
                        RequestParam(_context))
                else:
                    auth_endpoint.client_verification_method = [
                        RequestParam(_context)]
            else:  # pushed_authorization endpoint
                if isinstance(auth_endpoint.client_authn_method, list):
                    auth_endpoint.client_authn_method.append(
                        PrivateKeyJWT(_context))
                else:
                    auth_endpoint.client_authn_method = [
                        PrivateKeyJWT(_context)]

            _pi = _context.provider_info
            _supported = kwargs.get('client_registration_authn_methods_supported')
            if _supported:
                _pi['client_registration_authn_methods_supported'] = _supported
            # else:
            #     _pi['client_registration_authn_methods_supported'] = [
            #         _method.tag for _method in auth_endpoint.client_authn_method]
