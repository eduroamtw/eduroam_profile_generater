"""
Main application module for the eduroam profile generator.
"""

from typing import NoReturn

from src.utils import ensure_directories_exist, load_radius_info, log_results
from src.auth import spider_ustc_seesea, spider_local, analyze_logs
from src.profile import generate_profile


def main() -> NoReturn:
    """
    Main application entry point.
    """
    # Initialize environment
    ensure_directories_exist()

    # Get realm input
    realm_input = ""
    while not realm_input:
        realm_input = input("請輸入您想要產生設定檔的 realm (例如 mail.edu.tw): ")

    print(f"您輸入的 realm 是: {realm_input}")

    # Select server
    server_id = input("請選擇你想使用的伺服器\n0: 中國科大 (預設)\n1: 西安科大\n")

    print("正在連線認證伺服器並取得設定資訊，請稍後...")
    print("此過程約需要一分鐘左右。")

    # Test authentication
    realm, status_code = spider_ustc_seesea(realm_input, server_id)

    # For local testing (commented out)
    # radius_info = load_radius_info()
    # realm, status_code = spider_local(realm_input, radius_info)

    if status_code != 0:
        print("\n網頁下載失敗，請檢查網路連線或稍後再試。")
        return

    # Analyze authentication logs
    dns, mschapv2_stat, mschapv2_cert, pap_stat, pap_cert = analyze_logs(realm_input)

    # Log results
    log_results(realm, pap_stat, mschapv2_stat, dns, pap_cert, mschapv2_cert)

    if not (pap_stat or mschapv2_stat):
        exit()

    # Generate profile
    config_filename = generate_profile(
        realm=realm,
        name=realm,
        short_name=realm,
        mschapv2_stat=mschapv2_stat,
        pap_stat=pap_stat,
        dns=dns,
        url="https://edur.isli.me/",
        mschapv2_cert=mschapv2_cert,
        pap_cert=pap_cert,
    )

    if config_filename:
        print(f"\n設定檔 {config_filename} 產生成功！")
    else:
        print("\n設定檔產生失敗。")
