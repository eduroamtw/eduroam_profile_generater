"""
Custom exceptions for the eduroam profile generator.
"""


class EduroamError(Exception):
    """Base exception for eduroam profile generator."""

    pass


class AuthenticationError(EduroamError):
    """Raised when authentication fails."""

    pass


class CertificateError(EduroamError):
    """Raised when certificate processing fails."""

    pass


class ProfileGenerationError(EduroamError):
    """Raised when profile generation fails."""

    pass


class RateLimitError(EduroamError):
    """Raised when rate limit is exceeded."""

    pass


class NetworkError(EduroamError):
    """Raised when network request fails."""

    pass
