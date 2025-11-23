"""
Domain layer containing business models and rules.
"""

from src.domain.models import (
    AuthMethod,
    TestServer,
    Realm,
    Certificate,
    AuthenticationResult,
    ProfileConfig,
)
from src.domain.exceptions import (
    EduroamError,
    AuthenticationError,
    CertificateError,
    ProfileGenerationError,
    RateLimitError,
    NetworkError,
)

__all__ = [
    "AuthMethod",
    "TestServer",
    "Realm",
    "Certificate",
    "AuthenticationResult",
    "ProfileConfig",
    "EduroamError",
    "AuthenticationError",
    "CertificateError",
    "ProfileGenerationError",
    "RateLimitError",
    "NetworkError",
]
