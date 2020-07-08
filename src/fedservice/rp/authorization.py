from oidcservice.oidc.authorization import Authorization


class FedAuthorization(Authorization):
    default_authn_method = 'request_param'

    def __init__(self, service_context, client_authn_factory=None, conf=None):
        Authorization.__init__(self, service_context=service_context,
                               client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct.append(self._automatic_registration)

    def _automatic_registration(self, request_args, post_args=None, **kwargs):
        if post_args is None:
            post_args = {}

        pi = self.service_context.get('provider_info')
        _sup = pi.get('automatic_registration_client_authn_methods_supported')
        # what if request_param is already set ??
        # What if request_param in not in client_auth ??
        if _sup and 'request_param' in _sup:
            post_args['request_param'] = "request"

        return request_args, post_args
