class SIFRError(Exception):
    """Base exception for SIFR prototype failures."""


class SignatureError(SIFRError):
    pass


class MessageValidationError(SIFRError):
    pass


class CapabilityError(SIFRError):
    pass


class UnauthorizedAction(CapabilityError):
    pass


class AuditDAGError(SIFRError):
    pass


class RevocationError(SIFRError):
    pass


class ReplayError(SIFRError):
    pass


class CredentialError(SIFRError):
    pass
