"""
Certificate processing service.
"""

import re
from pathlib import Path
from typing import Optional

import requests

from src.domain import Certificate, CertificateError
from src.infrastructure import CommandExecutor, FileRepository


class CertificateService:
    """Service for certificate extraction and processing."""

    def __init__(
        self,
        file_repo: FileRepository,
        command_executor: CommandExecutor,
        cert_dir: Path,
        temp_dir: Path,
    ):
        self.file_repo = file_repo
        self.executor = command_executor
        self.cert_dir = cert_dir
        self.temp_dir = temp_dir

    def extract_from_log(self, log_content: str) -> Optional[str]:
        """
        Extract certificate hex from log content.

        Args:
            log_content: Log content containing certificate

        Returns:
            Certificate hex string or None if not found
        """
        pattern = r"\(handshake\/certificate\)\n.*?\): (.*)$"
        match = re.search(pattern, log_content, re.MULTILINE)

        if not match:
            return None

        openssl_hex = match.group(1)
        no_space_hex = re.sub(r"\s+", "", openssl_hex)

        # Find certificate header (0x3082 is the start of DER-encoded certificate)
        head_index = no_space_hex.find("3082")
        if head_index == -1:
            return None

        return no_space_hex[head_index:]

    def process_certificate(
        self, realm: str, method: str, cert_hex: str
    ) -> Certificate:
        """
        Process certificate from hex string.

        Args:
            realm: Domain realm
            method: Authentication method
            cert_hex: Hexadecimal certificate data

        Returns:
            Certificate object with DER and PEM data

        Raises:
            CertificateError: If certificate processing fails
        """
        try:
            # Convert hex to binary
            cert_der = bytes.fromhex(cert_hex)

            # Save DER certificate
            der_filename = f"{realm}-{method}-DER.der"
            der_path = self.cert_dir / der_filename
            self.file_repo.write_bytes(der_path, cert_der)

            # Convert to PEM
            pem_filename = f"{realm}-{method}-PEM.pem"
            pem_path = self.cert_dir / pem_filename

            result = self.executor.execute(
                ["openssl", "x509", "-in", str(der_path), "-inform", "DER", "-out", str(pem_path)]
            )

            if not result.success:
                raise CertificateError(f"Failed to convert DER to PEM: {result.stderr}")

            # Read PEM content
            pem_content = self.file_repo.read_text(pem_path)

            # Trace root CA certificate
            ca_cert_b64 = self.get_root_ca_cert(pem_filename)

            return Certificate(
                der_data=cert_der, pem_content=pem_content, ca_cert_b64=ca_cert_b64
            )

        except Exception as e:
            raise CertificateError(f"Failed to process certificate: {e}") from e

    def get_root_ca_cert(self, cert_filename: str) -> Optional[str]:
        """
        Get the root CA certificate for a given certificate.

        Args:
            cert_filename: Certificate filename

        Returns:
            Base64 encoded CA certificate without headers
        """
        target_cert_filename = f"root_{cert_filename}"
        source_path = self.cert_dir / cert_filename
        target_path = self.cert_dir / target_cert_filename

        # Copy the initial certificate
        self.file_repo.copy(source_path, target_path)

        # Trace certificate chain to root CA
        is_root_found = False
        while not is_root_found:
            log_path = self.temp_dir / "ca_trace.log"

            # Get authority information access extension
            result = self.executor.execute(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(target_path),
                    "-noout",
                    "-ext",
                    "authorityInfoAccess",
                ]
            )

            self.file_repo.write_text(log_path, result.stdout)
            log_content = self.file_repo.read_text(log_path)

            # Extract parent CA URL
            parent_ca_match = re.search(
                r"CA Issuers - URI:\s*(.+)", log_content, re.MULTILINE
            )

            if not parent_ca_match:
                # Root CA found (no parent)
                is_root_found = True
                continue

            # Download parent certificate
            parent_ca_url = parent_ca_match.group(1)
            try:
                response = requests.get(parent_ca_url, timeout=30)
                response.raise_for_status()
                self.file_repo.write_bytes(target_path, response.content)
            except requests.exceptions.RequestException:
                # Failed to download, assume current cert is root
                is_root_found = True

        # Convert to PEM if needed
        cert_content = self.file_repo.read_text(target_path, encoding="utf-8")
        is_pem = "-----BEGIN CERTIFICATE-----" in cert_content

        if not is_pem:
            # Convert DER to PEM
            temp_path = target_path.with_suffix(".tmp.pem")
            result = self.executor.execute(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(target_path),
                    "-inform",
                    "DER",
                    "-out",
                    str(temp_path),
                ]
            )

            if result.success:
                self.file_repo.copy(temp_path, target_path)
                cert_content = self.file_repo.read_text(target_path)

        # Remove headers and newlines to get base64 content
        cert_b64 = re.sub(
            r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n",
            "",
            cert_content,
        )

        return cert_b64
