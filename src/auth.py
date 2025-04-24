"""
Authentication and certificate handling for the eduroam profile generator.
"""

import os
import re
from typing import Dict, Tuple, Optional
import requests

from src.constants import (
    ACCOUNT,
    PASSWORD,
    TEMPLATE_DIR,
    USTC_SEESEA_HTML_DIR,
    EAPOL_TEST_LOG_DIR,
    EAPOL_TEST_CONF_DIR,
    EAPOL_TEST_CONF_PEAP_MSCHAPV2,
    EAPOL_TEST_CONF_TTLS_PAP,
    EAPOL_TEST_PROGRAM,
    CERT_DIR,
    USTC_URL,
    SEESEA_URL,
)
from src.utils import extract_cert_from_log, get_root_ca_cert


def spider_ustc_seesea(realm: str, server_id: str = "0") -> Tuple[str, int]:
    """
    Test authentication against USTC/SEESEA eduroam test servers.

    Args:
        realm: Domain realm (e.g., mail.edu.tw)
        server_id: Server ID (0: USTC, 1: SEESEA)

    Returns:
        Tuple of (realm, status_code)
        status_code: 0 for success, -1 for timeout
    """
    # Select server based on ID
    url = USTC_URL if server_id == "0" else SEESEA_URL

    # Format the test URL with credentials
    username = f"{ACCOUNT}@{realm}"
    test_url = f"{url}?login={requests.utils.quote(username)}&password={requests.utils.quote(PASSWORD)}"

    # Send request to test server
    try:
        response = requests.get(test_url)
        response.raise_for_status()

        # Save response content to HTML file
        html_file = USTC_SEESEA_HTML_DIR / f"{realm}.html"
        with open(html_file, "wb") as file:
            file.write(response.content)

        # Read the saved HTML file
        with open(html_file, "r", encoding="utf-8") as file:
            content = file.read()

        # Check for rate limiting
        if "每10分钟允许30个请求，请稍后再来测试" in content:
            print("請求過於頻繁，請稍後再試")
            return realm, -1

        # Extract MSCHAP v2 and PAP sections
        mschapv2_section = re.search(
            r'phase2="autheap=MSCHAPV2".*?\<pre\>\n(.*?)\n\<\/pre\>', content, re.DOTALL
        )
        pap_section = re.search(
            r'phase2="auth=PAP".*?\<pre\>\n(.*?)\n\<\/pre\>', content, re.DOTALL
        )

        # Save extracted log sections
        if mschapv2_section:
            eapol_mschapv2 = mschapv2_section.group(1)
            log_file = EAPOL_TEST_LOG_DIR / f"{realm}_PEAP_MSCHAPv2.log"
            with open(log_file, "w", encoding="utf-8") as file:
                file.write(eapol_mschapv2)

        if pap_section:
            eapol_pap = pap_section.group(1)
            log_file = EAPOL_TEST_LOG_DIR / f"{realm}_TTLS_PAP.log"
            with open(log_file, "w", encoding="utf-8") as file:
                file.write(eapol_pap)

        return realm, 0

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to test server: {e}")
        return realm, -1


def spider_local(realm: str, radius_info: Dict[str, str]) -> Tuple[str, int]:
    """
    Test authentication against local radius server.

    Args:
        realm: Domain realm (e.g., mail.edu.tw)
        radius_info: Dict containing radius_ip and radius_key

    Returns:
        Tuple of (realm, status_code)
        status_code: 0 for success
    """
    radius_ip = radius_info["radius_ip"]
    radius_key = radius_info["radius_key"]

    # Generate PEAP MSCHAPv2 config
    mschapv2_template_path = TEMPLATE_DIR / EAPOL_TEST_CONF_PEAP_MSCHAPV2
    with open(mschapv2_template_path, "r", encoding="utf-8") as file:
        mschapv2_conf = (
            file.read()
            .replace("#Username#", ACCOUNT)
            .replace("#Realm#", realm)
            .replace("#Password#", PASSWORD)
        )

    mschapv2_conf_path = EAPOL_TEST_CONF_DIR / f"{realm}_PEAP_MSCHAPv2.conf"
    with open(mschapv2_conf_path, "w", encoding="utf-8") as file:
        file.write(mschapv2_conf)

    # Generate TTLS PAP config
    pap_template_path = TEMPLATE_DIR / EAPOL_TEST_CONF_TTLS_PAP
    with open(pap_template_path, "r", encoding="utf-8") as file:
        pap_conf = (
            file.read()
            .replace("#Username#", ACCOUNT)
            .replace("#Realm#", realm)
            .replace("#Password#", PASSWORD)
        )

    pap_conf_path = EAPOL_TEST_CONF_DIR / f"{realm}_TTLS_PAP.conf"
    with open(pap_conf_path, "w", encoding="utf-8") as file:
        file.write(pap_conf)

    # Run tests using eapol_test
    mschapv2_log_path = EAPOL_TEST_LOG_DIR / f"{realm}_PEAP_MSCHAPv2.log"
    pap_log_path = EAPOL_TEST_LOG_DIR / f"{realm}_TTLS_PAP.log"

    os.system(
        f"{EAPOL_TEST_PROGRAM} -c {mschapv2_conf_path} -a {radius_ip} "
        f"-s {radius_key} > {mschapv2_log_path}"
    )

    os.system(
        f"{EAPOL_TEST_PROGRAM} -c {pap_conf_path} -a {radius_ip} "
        f"-s {radius_key} > {pap_log_path}"
    )

    return realm, 0


def analyze_logs(
    realm: str,
) -> Tuple[Optional[str], bool, Optional[str], bool, Optional[str]]:
    """
    Analyze eapol test logs for a given realm.

    Args:
        realm: Domain realm (e.g., mail.edu.tw)

    Returns:
        Tuple of (dns_value, mschapv2_stat, mschapv2_cert, pap_stat, pap_cert)
    """
    # Read log files
    mschapv2_log_path = EAPOL_TEST_LOG_DIR / f"{realm}_PEAP_MSCHAPv2.log"
    pap_log_path = EAPOL_TEST_LOG_DIR / f"{realm}_TTLS_PAP.log"

    with open(mschapv2_log_path, "r", encoding="utf-8") as file:
        mschapv2_content = file.read()

    with open(pap_log_path, "r", encoding="utf-8") as file:
        pap_content = file.read()

    # Extract DNS information
    dns_value = None
    dns_match_mschapv2 = re.search(r"DNS:\s*(.+)", mschapv2_content)
    dns_match_pap = re.search(r"DNS:\s*(.+)", pap_content)

    if dns_match_mschapv2:
        dns_value = dns_match_mschapv2.group(1).strip()
        print('DNS: "', dns_value, '"', sep="")
    elif dns_match_pap:
        dns_value = dns_match_pap.group(1).strip()
        print('DNS: "', dns_value, '"', sep="")
    else:
        print("未找到 DNS 資訊")

    # Check for handshake/certificate in logs
    mschapv2_stat = bool(
        re.search(r"\(handshake\/certificate\)", mschapv2_content, re.DOTALL)
    )
    pap_stat = bool(re.search(r"\(handshake\/certificate\)", pap_content, re.DOTALL))

    print("偵測開始...")

    # Process certificates
    mschapv2_cert = None
    pap_cert = None

    if mschapv2_stat and pap_stat:
        print("MSCHAP v2 / PAP 憑證已拿取")
        mschapv2_cert = process_certificate(realm, "PEAP-MSCHAPv2", mschapv2_content)
        pap_cert = process_certificate(realm, "TTLS-PAP", pap_content)
    elif pap_stat:
        print("PAP 憑證已拿取 / MSCHAP v2 憑證未拿取")
        pap_cert = process_certificate(realm, "TTLS-PAP", pap_content)
    elif mschapv2_stat:
        print("MSCHAP v2 憑證已拿取 / PAP 憑證未拿取")
        mschapv2_cert = process_certificate(realm, "PEAP-MSCHAPv2", mschapv2_content)
    else:
        print("MSCHAP v2 / PAP 憑證未拿取，未知的錯誤")

    return dns_value, mschapv2_stat, mschapv2_cert, pap_stat, pap_cert


def process_certificate(realm: str, method: str, cert_content: str) -> Optional[str]:
    """
    Process certificate from log content.

    Args:
        realm: Domain realm
        method: Authentication method (PEAP-MSCHAPv2 or TTLS-PAP)
        cert_content: Log content containing certificate

    Returns:
        Base64 encoded CA certificate
    """
    cert_hex = extract_cert_from_log(cert_content)
    if not cert_hex:
        print("憑證未找到")
        return None

    try:
        # Convert hex to binary
        cert_der = bytes.fromhex(cert_hex)

        # Save DER certificate
        der_filename = f"{realm}-{method}-DER.der"
        der_path = CERT_DIR / der_filename
        with open(der_path, "wb") as file:
            file.write(cert_der)

        # Convert to PEM and save
        pem_filename = f"{realm}-{method}-PEM.pem"
        pem_path = CERT_DIR / pem_filename
        os.system(f"openssl x509 -in {der_path} -inform DER -out {pem_path}")

        # Trace root CA certificate
        ca_cert = get_root_ca_cert(pem_filename)
        return ca_cert

    except Exception as e:
        print(f"Error processing certificate: {e}")
        return None
