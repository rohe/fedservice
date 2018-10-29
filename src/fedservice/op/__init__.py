from oidcendpoint import endpoint_context


class EndpointContext(endpoint_context.EndpointContext):
    def __init__(self, conf, keyjar=None, client_db=None, session_db=None,
                 cwd='', cookie_dealer=None, federation_entity=None):
        endpoint_context.EndpointContext.__init__(
            self, conf, keyjar=keyjar, client_db=client_db,
            session_db=session_db, cwd=cwd, cookie_dealer=cookie_dealer)

        self.federation_entity = federation_entity
