"""
Utility functions for the eduroam profile generator.
"""

import os
import json
import csv
import datetime
import re
import shutil
import subprocess
from pathlib import Path
import requests
from typing import Dict, Optional

from src.constants import (
    TEMPLATE_DIR,
    PROFILE_DIR,
    CERT_DIR,
    LOG_DIR,
    USTC_SEESEA_HTML_DIR,
    EAPOL_TEST_LOG_DIR,
    EAPOL_TEST_CONF_DIR,
    TEMP_DIR,
    LOG_FILENAME,
    CA_TRACE_TEMP,
)


def ensure_directories_exist() -> None:
    """
    Ensure all required directories exist.
    """
    for directory in (
        TEMPLATE_DIR,
        PROFILE_DIR,
        CERT_DIR,
        LOG_DIR,
        USTC_SEESEA_HTML_DIR,
        EAPOL_TEST_LOG_DIR,
        EAPOL_TEST_CONF_DIR,
        TEMP_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    # Initialize log file if it doesn't exist
    log_file = LOG_DIR / LOG_FILENAME
    if not log_file.exists():
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("Time,realm,pap_stat,mschapv2_stat,dns,cert_pap,cert_mschapv2\n")

    # Initialize radius.json if it doesn't exist
    radius_file = Path("./radius.json")
    if not radius_file.exists():
        with open(radius_file, "w", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {"radius_ip": "127.0.0.1", "radius_key": "testing123"}, indent=4
                )
            )


def load_radius_info() -> Dict[str, str]:
    """
    Load radius server information from radius.json.

    Returns:
        Dict containing radius_ip and radius_key.
    """
    with open("radius.json", "r") as f:
        return json.load(f)


def log_results(
    realm: str,
    pap_stat: bool,
    mschapv2_stat: bool,
    dns: str,
    pap_cert: str,
    mschapv2_cert: str,
    filename: Path = LOG_DIR / LOG_FILENAME,
) -> None:
    """
    Log results to CSV file.

    Args:
        realm: Domain realm
        pap_stat: PAP authentication status
        mschapv2_stat: MSCHAPv2 authentication status
        dns: DNS server
        pap_cert: PAP certificate
        mschapv2_cert: MSCHAPv2 certificate
        filename: Path to log file
    """
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(filename, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            [current_time, realm, pap_stat, mschapv2_stat, dns, pap_cert, mschapv2_cert]
        )


def run_command(command: str) -> str:
    """
    Run a shell command and return the output.

    Args:
        command: The command to run

    Returns:
        Command output as string
    """
    process = subprocess.run(
        command, shell=True, capture_output=True, text=True, check=False
    )
    return process.stdout


def extract_cert_from_log(cert_content: str) -> Optional[str]:
    """
    Extract certificate hex from log content.

    Args:
        cert_content: Log content containing certificate

    Returns:
        Certificate hex string or None if not found
    """
    openssl_hex_regex = re.search(
        r"\(handshake\/certificate\)\n.*?\): (.*)$", cert_content, re.MULTILINE
    )

    if not openssl_hex_regex:
        print("憑證未找到")
        return None
    openssl_hex = openssl_hex_regex.group(1)
    no_space_hex = re.sub(r"\s+", "", openssl_hex)

    # Find certificate head
    head_index = no_space_hex.find("3082")
    if head_index == -1:
        return None

    return no_space_hex[head_index:]


def get_root_ca_cert(cert_filename: str) -> Optional[str]:
    """
    Get the root CA certificate for a given certificate file.

    Args:
        cert_filename: The filename of the certificate

    Returns:
        Base64 encoded CA certificate content without headers
    """
    target_cert_filename = f"root_{cert_filename}"
    source_path = CERT_DIR / cert_filename
    target_path = CERT_DIR / target_cert_filename

    # Copy the initial certificate
    shutil.copy(source_path, target_path)

    # Trace the certificate chain to the root CA
    is_root_found = False
    while not is_root_found:
        log_path = TEMP_DIR / CA_TRACE_TEMP

        # Get authority information access extension
        cmd = f"openssl x509 -in {target_path} -noout -ext authorityInfoAccess > {log_path}"
        os.system(cmd)

        with open(log_path, "r", encoding="utf-8") as file:
            getcalog = file.read()

        # Extract parent CA URL
        parent_ca_url_match = re.search(
            r"CA Issuers - URI:\s*(.+)", getcalog, re.MULTILINE
        )

        if not parent_ca_url_match:
            # Root CA found (no parent)
            is_root_found = True
            continue

        # Download parent certificate
        parent_ca_url = parent_ca_url_match.group(1)
        try:
            response = requests.get(parent_ca_url)
            response.raise_for_status()

            with open(target_path, "wb") as file:
                file.write(response.content)

        except requests.exceptions.RequestException:
            print(f"Failed to download CA certificate from {parent_ca_url}")
            is_root_found = True

    # Check if certificate is in DER format and convert to PEM if needed
    with open(target_path, "r", encoding="utf-8", errors="ignore") as file:
        cert_content = file.read()

    is_pem = "-----BEGIN CERTIFICATE-----" in cert_content

    if not is_pem:
        # Convert DER to PEM
        temp_path = target_path.with_suffix(".tmp.pem")
        os.system(f"openssl x509 -in {target_path} -inform DER -out {temp_path}")
        shutil.move(temp_path, target_path)

        with open(target_path, "r", encoding="utf-8") as file:
            cert_content = file.read()

    # Remove headers and newlines to get base64 encoded content
    cert_b64 = re.sub(
        r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n", "", cert_content
    )

    return cert_b64
