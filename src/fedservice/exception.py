class FedServiceError(Exception):
    pass


class NoSuitableFederation(FedServiceError):
    pass


class NoTrustedClaims(FedServiceError):
    pass


class DbFault(FedServiceError):
    pass
