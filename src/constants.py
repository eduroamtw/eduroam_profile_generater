"""
Constants for the eduroam profile generator.
"""

from pathlib import Path

# Account settings
ACCOUNT = "anonymous"
PASSWORD = "TestViaEduroamTWProfileProj"

# Paths
TEMPLATE_DIR = Path("template")
OUTPUT_DIR = Path("output")

PROFILE_DIR = OUTPUT_DIR / "profile"
CERT_DIR = OUTPUT_DIR / "cert"
LOG_DIR = OUTPUT_DIR / "log"
USTC_SEESEA_HTML_DIR = OUTPUT_DIR / "log/ustc_seesea_html"
EAPOL_TEST_LOG_DIR = OUTPUT_DIR / "log/eapol_log"
EAPOL_TEST_CONF_DIR = OUTPUT_DIR / "log/eapol_conf"
TEMP_DIR = OUTPUT_DIR / "temp"

# Filenames
GETEDUROAM_TEMPLATE_BOTH = "eduroam-eap-generic-anonymous-Both.eap-config"
GETEDUROAM_TEMPLATE_PEAP_MSCHAPV2 = (
    "eduroam-eap-generic-anonymous-PEAP-MSCHAPv2.eap-config"
)
GETEDUROAM_TEMPLATE_TTLS_PAP = "eduroam-eap-generic-anonymous-TTLS-PAP.eap-config"
EAPOL_TEST_CONF_PEAP_MSCHAPV2 = "eapol_test_PEAP-MSCHAPv2.conf"
EAPOL_TEST_CONF_TTLS_PAP = "eapol_test_TTLS_PAP.conf"
EAPOL_TEST_PROGRAM = "eapol_test.exe"
LOG_FILENAME = "log.csv"

# Temp filenames
EAPOL_CONF_TEMP = "eapol.conf"
CA_TRACE_TEMP = "getca.log"

# URLs
USTC_URL = "https://eduroam.ustc.edu.cn/cgi-bin/eduroam-test.cgi"
SEESEA_URL = "http://eduroam.seesea.site/cgi-bin/eduroam-test.cgi"
