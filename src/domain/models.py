"""
Domain models for the eduroam profile generator.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AuthMethod(Enum):
    """Authentication methods supported by eduroam."""

    PEAP_MSCHAPV2 = "PEAP-MSCHAPv2"
    TTLS_PAP = "TTLS-PAP"


class TestServer(Enum):
    """Available eduroam test servers."""

    USTC = ("0", "https://eduroam.ustc.edu.cn/cgi-bin/eduroam-test.cgi")
    SEESEA = ("1", "http://eduroam.seesea.site/cgi-bin/eduroam-test.cgi")

    def __init__(self, server_id: str, url: str):
        self.server_id = server_id
        self.url = url

    @classmethod
    def from_id(cls, server_id: str) -> "TestServer":
        """Get server by ID."""
        for server in cls:
            if server.server_id == server_id:
                return server
        return cls.USTC


@dataclass(frozen=True)
class Realm:
    """Represents an eduroam realm (domain)."""

    value: str

    def __post_init__(self):
        if not self.value:
            raise ValueError("Realm cannot be empty")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Certificate:
    """Represents a TLS certificate."""

    der_data: bytes
    pem_content: str
    ca_cert_b64: Optional[str] = None

    @property
    def has_root_ca(self) -> bool:
        """Check if root CA certificate is available."""
        return self.ca_cert_b64 is not None


@dataclass(frozen=True)
class AuthenticationResult:
    """Result of an authentication test."""

    realm: Realm
    dns: Optional[str]
    mschapv2_success: bool
    pap_success: bool
    mschapv2_cert: Optional[Certificate] = None
    pap_cert: Optional[Certificate] = None

    @property
    def has_any_success(self) -> bool:
        """Check if any authentication method succeeded."""
        return self.mschapv2_success or self.pap_success

    @property
    def supported_methods(self) -> list[AuthMethod]:
        """Get list of supported authentication methods."""
        methods = []
        if self.mschapv2_success:
            methods.append(AuthMethod.PEAP_MSCHAPV2)
        if self.pap_success:
            methods.append(AuthMethod.TTLS_PAP)
        return methods


@dataclass(frozen=True)
class ProfileConfig:
    """Configuration for generating eduroam profile."""

    realm: Realm
    name: str
    short_name: str
    dns: Optional[str]
    url: str
    email: str
    mschapv2_cert: Optional[str] = None
    pap_cert: Optional[str] = None

    @property
    def supports_both_methods(self) -> bool:
        """Check if both authentication methods are supported."""
        return self.mschapv2_cert is not None and self.pap_cert is not None

    @property
    def supports_mschapv2_only(self) -> bool:
        """Check if only MSCHAPv2 is supported."""
        return self.mschapv2_cert is not None and self.pap_cert is None

    @property
    def supports_pap_only(self) -> bool:
        """Check if only PAP is supported."""
        return self.pap_cert is not None and self.mschapv2_cert is None
