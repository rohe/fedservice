class FedServiceError(Exception):
    pass


class NoSuitableFederation(FedServiceError):
    pass


class NoTrustedClaims(FedServiceError):
    pass


class DbFault(FedServiceError):
    pass


class WrongSubject(FedServiceError):
    pass


class ConstraintError(FedServiceError):
    pass


class UnknownCertificate(FedServiceError):
    pass


class UnknownEntity(FedServiceError):
    pass


class UnknownCriticalExtension(FedServiceError):
    pass