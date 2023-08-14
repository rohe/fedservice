class FedServiceError(Exception):
    pass


class NoSuitableFederation(FedServiceError):
    pass


class NoTrustedChains(FedServiceError):
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


class FailedConfigurationRetrieval(Exception):
    pass


class SignatureFailure(FedServiceError):
    pass


class FailedInformationRetrieval(Exception):
    pass
