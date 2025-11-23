"""
Authentication testing service.
"""

import re
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests

from src.domain import (
    Realm,
    AuthenticationResult,
    Certificate,
    TestServer,
    AuthMethod,
    RateLimitError,
    NetworkError,
)
from src.infrastructure import FileRepository
from src.services.certificate_service import CertificateService


class AuthenticationService:
    """Service for testing eduroam authentication."""

    def __init__(
        self,
        file_repo: FileRepository,
        cert_service: CertificateService,
        log_dir: Path,
        account: str = "anonymous",
        password: str = "TestViaEduroamTWProfileProj",
    ):
        self.file_repo = file_repo
        self.cert_service = cert_service
        self.log_dir = log_dir
        self.account = account
        self.password = password

    def test_authentication(
        self, realm: Realm, server: TestServer
    ) -> AuthenticationResult:
        """
        Test authentication against eduroam test server.

        Args:
            realm: Domain realm
            server: Test server to use

        Returns:
            AuthenticationResult containing test results

        Raises:
            RateLimitError: If rate limit is exceeded
            NetworkError: If network request fails
        """
        # Build test URL
        username = f"{self.account}@{realm}"
        test_url = f"{server.url}?login={quote(username)}&password={quote(self.password)}"

        # Send request
        try:
            response = requests.get(test_url, timeout=120)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Failed to connect to test server: {e}") from e

        # Save HTML response
        html_file = self.log_dir / "ustc_seesea_html" / f"{realm}.html"
        self.file_repo.ensure_directory(html_file.parent)
        self.file_repo.write_bytes(html_file, response.content)

        # Parse HTML content
        content = self.file_repo.read_text(html_file)

        # Check for rate limiting
        if "每10分钟允许30个请求，请稍后再来测试" in content:
            raise RateLimitError("請求過於頻繁，請稍後再試")

        # Extract log sections
        mschapv2_log = self._extract_log_section(
            content, r'phase2="autheap=MSCHAPV2".*?\<pre\>\n(.*?)\n\<\/pre\>'
        )
        pap_log = self._extract_log_section(
            content, r'phase2="auth=PAP".*?\<pre\>\n(.*?)\n\<\/pre\>'
        )

        # Save logs
        if mschapv2_log:
            log_file = self.log_dir / "eapol_log" / f"{realm}_PEAP_MSCHAPv2.log"
            self.file_repo.ensure_directory(log_file.parent)
            self.file_repo.write_text(log_file, mschapv2_log)

        if pap_log:
            log_file = self.log_dir / "eapol_log" / f"{realm}_TTLS_PAP.log"
            self.file_repo.ensure_directory(log_file.parent)
            self.file_repo.write_text(log_file, pap_log)

        # Analyze logs
        return self._analyze_logs(realm, mschapv2_log, pap_log)

    def _extract_log_section(self, content: str, pattern: str) -> Optional[str]:
        """Extract log section from HTML content."""
        match = re.search(pattern, content, re.DOTALL)
        return match.group(1) if match else None

    def _analyze_logs(
        self, realm: Realm, mschapv2_log: Optional[str], pap_log: Optional[str]
    ) -> AuthenticationResult:
        """
        Analyze authentication logs.

        Args:
            realm: Domain realm
            mschapv2_log: MSCHAPv2 log content
            pap_log: PAP log content

        Returns:
            AuthenticationResult
        """
        # Extract DNS
        dns = None
        if mschapv2_log:
            dns = self._extract_dns(mschapv2_log)
        if not dns and pap_log:
            dns = self._extract_dns(pap_log)

        # Check for successful handshake
        mschapv2_success = (
            bool(re.search(r"\(handshake\/certificate\)", mschapv2_log, re.DOTALL))
            if mschapv2_log
            else False
        )
        pap_success = (
            bool(re.search(r"\(handshake\/certificate\)", pap_log, re.DOTALL))
            if pap_log
            else False
        )

        # Process certificates
        mschapv2_cert = None
        pap_cert = None

        if mschapv2_success and mschapv2_log:
            mschapv2_cert = self._process_certificate(
                str(realm), AuthMethod.PEAP_MSCHAPV2.value, mschapv2_log
            )

        if pap_success and pap_log:
            pap_cert = self._process_certificate(
                str(realm), AuthMethod.TTLS_PAP.value, pap_log
            )

        return AuthenticationResult(
            realm=realm,
            dns=dns,
            mschapv2_success=mschapv2_success,
            pap_success=pap_success,
            mschapv2_cert=mschapv2_cert,
            pap_cert=pap_cert,
        )

    def _extract_dns(self, log_content: str) -> Optional[str]:
        """Extract DNS from log content."""
        match = re.search(r"DNS:\s*(.+)", log_content)
        return match.group(1).strip() if match else None

    def _process_certificate(
        self, realm: str, method: str, log_content: str
    ) -> Optional[Certificate]:
        """Process certificate from log content."""
        cert_hex = self.cert_service.extract_from_log(log_content)
        if not cert_hex:
            return None

        try:
            return self.cert_service.process_certificate(realm, method, cert_hex)
        except Exception:
            return None
