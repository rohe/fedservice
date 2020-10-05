from oidcservice.exception import OtherError
from oidcservice.oidc.authorization import Authorization


class FedAuthorization(Authorization):

    def __init__(self, service_context, client_authn_factory=None, conf=None):
        Authorization.__init__(self, service_context=service_context,
                               client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct.append(self._automatic_registration)

    def _automatic_registration(self, request_args, post_args=None, **kwargs):
        if post_args is None:
            post_args = {}

        pi = self.service_context.get('provider_info')
        _ams = pi.get('client_registration_authn_methods_supported')
        # what if request_param is already set ??
        # What if request_param in not in client_auth ??
        if _ams and 'ar' in _ams:
            if "request_object" in _ams['ar']:
                post_args['request_param'] = "request"
                post_args['audience'] = "authorization_endpoint"
                post_args["with_jti"] = True
            else:
                raise OtherError("Using request object in authentication not supported")
        else: # no authn methods supported
            # am I already registered ?
            if self.service_context.get('registration_response') is None:  # Not registered
                raise OtherError("Can not send an authorization request without being registered"
                                 " and automatic registration not supported")

        return request_args, post_args
