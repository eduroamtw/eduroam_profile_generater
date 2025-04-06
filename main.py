import subprocess
import re
import shutil
import requests
import csv
import os
import base64
import datetime
import json
# from cryptography import x509

# 帳號設定
account = "anonymous"
password = "TestViaEduroamTWProfileProj"

# 輸出位置
template_path = "./template"
profile_path = "./output/profile"
cert_path = "./output/cert"
log_path = "./output/log"
ustc_seesea_html_path = "./output/log/ustc_seesea_html"
eapol_test_log_path = "./output/log/eapol_log"
eapol_test_conf_path = "./output/log/eapol_conf"
temp_path = "./output/temp"

# 檔案名稱設定
geteduroam_template_both_filename = "eduroam-eap-generic-anonymous-Both.eap-config"
geteduroam_template_peap_mschapv2_filename = "eduroam-eap-generic-anonymous-PEAP-MSCHAPv2.eap-config"
geteduroam_template_ttls_pap_filename = "eduroam-eap-generic-anonymous-TTLS-PAP.eap-config"
eapol_test_conf_peap_mschapv2_filename = "eapol_test_PEAP-MSCHAPv2.conf"
eapol_test_conf_ttls_pap_filename = "eapol_test_TTLS_PAP.conf"
eapol_test_program_path = "eapol_test.exe"
log_filename = "log.csv"

eapol_test_conf_temp_filename = "eapol.conf"
ca_trace_temp_filename = "getca.log"

def environment_test():
    if not os.path.isdir(template_path):
        os.makedirs(template_path)
    if not os.path.isdir(profile_path):
        os.makedirs(profile_path)
    if not os.path.isdir(cert_path):
        os.makedirs(cert_path)
    if not os.path.isdir(ustc_seesea_html_path):
        os.makedirs(ustc_seesea_html_path)
    if not os.path.isdir(eapol_test_log_path):
        os.makedirs(eapol_test_log_path)
    if not os.path.isdir(eapol_test_conf_path):
        os.makedirs(eapol_test_conf_path)
    if not os.path.isdir(temp_path):
        os.makedirs(temp_path)
    if not os.path.isfile(log_path + "/" + log_filename):
        with open(log_path + "/" + log_filename, "w", encoding="utf-8") as file:
            file.write("Time,realm,pap_stat,mschapv2_stat,dns,cert_pap,cert_mschapv2\n")
    if not os.path.isfile("./radius.json"):
        with open("./radius.json", "w", encoding="utf-8") as file:
            file.write("{\n    \"radius_ip\": \"127.0.0.1\",\n    \"radius_key\": \"testing123\"\n}")
    return 0

def spider_ustc_seesea(realm,source):
    """
    傳入 realm (如 mail.edu.tw)
    回傳 realm,status_code
    status_code =
    0 正常
    -1 timeout
    """

    # 爬網頁
    if source == 1:
        url = "http://eduroam.seesea.site/cgi-bin/eduroam-test.cgi"
    else:
        url = "https://eduroam.ustc.edu.cn/cgi-bin/eduroam-test.cgi"

    send_url = f"{url}?login={requests.utils.quote(account + "@" + realm)}&password={requests.utils.quote(password)}"
    response = requests.get(send_url)

    with open(ustc_seesea_html_path + "/" + realm + ".html", "wb") as file:
        file.write(response.content)

    # 讀取 ustc_seesea_html_path + "/" + realm + ".html" 檔案內容
    with open(ustc_seesea_html_path + "/" + realm + ".html", "r", encoding="utf-8") as file:
        content = file.read()

    timeout = re.search(r"每10分钟允许30个请求，请稍后再来测试", content,re.DOTALL)

    if timeout:
        print("請求過於頻繁，請稍後再試")
        status_code = -1
    else:
        status_code = 0

    # 擷取 MSCHAP v2 和 PAP 區段
    mschapv2_section = re.search(r"phase2=\"autheap=MSCHAPV2\".*?\<pre\>\n(.*?)\n\<\/pre\>", content, re.DOTALL)
    pap_section = re.search(r"phase2=\"auth=PAP\".*?\<pre\>\n(.*?)\n\<\/pre\>", content, re.DOTALL)

    if mschapv2_section:
        eapol_mschapv2 = mschapv2_section.group(1)
        with open(eapol_test_log_path + "/" + realm + "_PEAP_MSCHAPv2.log", "w", encoding="utf-8") as file:
            file.write(eapol_mschapv2)

    if pap_section:
        eapol_pap = pap_section.group(1)
        with open(eapol_test_log_path + "/" + realm + "_TTLS_PAP.log", "w", encoding="utf-8") as file:
            file.write(eapol_pap)
    return realm,status_code

def spider_local(realm):
    """
    傳入 realm (如 mail.edu.tw)
    回傳 realm,status_code
    status_code =
    0 正常
    """
    with open('radius.json', 'r') as radius:
        radius_info = json.load(radius)
    radius_ip = radius_info["radius_ip"]
    radius_key = radius_info["radius_key"]

    with open(template_path + "/" + eapol_test_conf_peap_mschapv2_filename, "r", encoding="utf-8") as file:
        eapol_test_conf_peap_mschapv2 = file.read()
    eapol_test_conf_peap_mschapv2 = eapol_test_conf_peap_mschapv2.replace('#Username#', account)
    eapol_test_conf_peap_mschapv2 = eapol_test_conf_peap_mschapv2.replace('#Realm#', realm)
    eapol_test_conf_peap_mschapv2 = eapol_test_conf_peap_mschapv2.replace('#Password#', password)
    with open(eapol_test_conf_path + "/" + realm + "_PEAP_MSCHAPv2.conf", "w", encoding="utf-8") as file:
        file.write(eapol_test_conf_peap_mschapv2)

    with open(template_path + "/" + eapol_test_conf_ttls_pap_filename, "r", encoding="utf-8") as file:
        eapol_test_conf_ttls_pap = file.read()
    eapol_test_conf_ttls_pap = eapol_test_conf_ttls_pap.replace('#Username#', account)
    eapol_test_conf_ttls_pap = eapol_test_conf_ttls_pap.replace('#Realm#', realm)
    eapol_test_conf_ttls_pap = eapol_test_conf_ttls_pap.replace('#Password#', password)
    with open(eapol_test_conf_path + "/" + realm + "_TTLS_PAP.conf", "w", encoding="utf-8") as file:
        file.write(eapol_test_conf_ttls_pap)

    os.system(f"{eapol_test_program_path} -c {eapol_test_conf_path}/{realm}_PEAP_MSCHAPv2.conf -a {radius_ip} -s {radius_key} -o test > {eapol_test_log_path}/{realm}_PEAP_MSCHAPv2.log")
    os.system(f"{eapol_test_program_path} -c {eapol_test_conf_path}/{realm}_TTLS_PAP.conf -a {radius_ip} -s {radius_key} -o test2 > {eapol_test_log_path}/{realm}_TTLS_PAP.log")
    status_code = 0
    return realm,status_code

def web_log_analyze(realm):
    """
    傳入 realm (如 mail.edu.tw)
    回傳 DNS,PEAP-MSCHAPv2 Status,PEAP-MSCHAPv2 Cert (Base64),TTLS-PAP Status,TTLS-PAP Cert (Base64)
    """
    # 解決變數範圍問題
    mschapv2_found = False
    pap_found = False

    with open(eapol_test_log_path + "/" + realm + "_PEAP_MSCHAPv2.log", "r", encoding="utf-8") as file:
        content_mschapv2 = file.read()
    with open(eapol_test_log_path + "/" + realm + "_TTLS_PAP.log", "r", encoding="utf-8") as file:
        content_pap = file.read()
    
    # 讀取 DNS
    match_mschapv2_regex = re.search(r"DNS:\s*(.+)", content_mschapv2)
    if match_mschapv2_regex:
        dns_value = match_mschapv2_regex.group(1).strip() 
        print("DNS: \"", dns_value, "\"", sep="")
    else:
        match_pap_regex = re.search(r"DNS:\s*(.+)", content_pap)
        if match_pap_regex:
            dns_value = match_pap_regex.group(1).strip() 
            print("DNS: \"", dns_value, "\"", sep="")
        else:
            dns_value = "NULL"
            print("未找到 DNS 資訊")
    
    # 檢查是否在對應區段內找到 "(handshake/certificate)"
    mschapv2_cert_regex = re.search(r"\(handshake\/certificate\)", content_mschapv2, re.DOTALL)
    if mschapv2_cert_regex:
        mschapv2_found = True
    pap_cert_regex = re.search(r"\(handshake\/certificate\)", content_pap, re.DOTALL)
    if pap_cert_regex:
        pap_found = True

    print("偵測開始...")

    # 判斷並輸出結果
    if mschapv2_found and pap_found == True:
        print("MSCHAP v2 / PAP 憑證已拿取")
        mschapv2_cert = web_export_cert(realm, "PEAP-MSCHAPv2", content_mschapv2)
        pap_cert = web_export_cert(realm, "TTLS-PAP", content_pap)
    elif pap_found == True:
        print("PAP 憑證已拿取 / MSCHAP v2 憑證未拿取")
        mschapv2_cert = "NULL"
        pap_cert = web_export_cert(realm, "TTLS-PAP", content_pap)
    elif mschapv2_found  == True:
        print("MSCHAP v2 憑證已拿取 / PAP 憑證未拿取")
        mschapv2_cert = web_export_cert(realm, "PEAP-MSCHAPv2", content_mschapv2)
        pap_cert = "NULL"
    else:
        print("MSCHAP v2 / PAP 憑證未拿取，未知的錯誤")
        mschapv2_cert = "NULL"
        pap_cert = "NULL"

    return dns_value, mschapv2_found, mschapv2_cert, pap_found, pap_cert

def web_export_cert(filename,method,cert_content): # 傳入整段 log
    """
    傳入 filename,method,cert_content
    回傳 base64 憑證檔內容 (去頭去尾)
    同時將 Binary 憑證檔另存一份為 filename + "-" + method + "-cert.crt"
    """
    openssl_hex_regex = re.search(r"\(handshake\/certificate\)\n.*?\): (.*)$", cert_content, re.MULTILINE)
    
    if openssl_hex_regex:  # 確保找到了匹配 (openssl_hex_regex 不是 None)
        openssl_hex = openssl_hex_regex.group(1)  # 提取第一個捕獲組的內容
        # 現在 openssl_hex 是一個字串，你可以安全地使用它
    else:
        print("憑證未找到")# 輸出憑證
    no_space_hex = re.sub(r"\s+", "", openssl_hex)  # 去除所有空白字符
    # 找憑證頭
    head_index = no_space_hex.find("3082")
    cert_hex = no_space_hex[head_index:]
    cert_der = bytes.fromhex(cert_hex)
    # 憑證 DER 檔
    filename_der = filename + "-" + method + "-DER.der"
    with open(cert_path + "/" + filename_der, "wb") as file:
        file.write(cert_der)
    # 憑證 PEM 檔
    filename_pem = filename + "-" + method + "-PEM.pem"
    os.system(f"openssl x509 -in {cert_path}/{filename_der} -inform DER -out {cert_path}/{filename_pem}")
    return_value = trace_root_ca(filename_pem)
    return return_value

def trace_root_ca(cert_filename):
    # 取得最上層 CA 憑證
    cacert = getca(cert_filename) # 回傳 CA Cert 檔名

    # if der to pem
    rootder_regex = re.search(r"-----BEGIN CERTIFICATE-----", cacert, re.MULTILINE)
    if rootder_regex == None:
        os.system(f"openssl x509 -in {cert_path}/{cacert} -inform DER -out {cert_path}/{cacert}")        

    # 讀 CA 憑證
    with open(cert_path + "/" + cacert, "r", encoding="utf-8") as file:
        cert_pem = file.read()
    
    # 去頭去尾去\n
    cert_b64 = re.sub(r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n", "", cert_pem)
    return cert_b64

def getca(cert_filename):
    target_cert_filename = "root_" + cert_filename
    shutil.copy(cert_path + "/" + cert_filename, cert_path + "/" + target_cert_filename)
    status = 0
    while status == 0:
        os.system(f"openssl x509 -in {cert_path}/{target_cert_filename} -noout -ext authorityInfoAccess > {temp_path}/{ca_trace_temp_filename}")
        with open(temp_path + "/" + ca_trace_temp_filename, "r", encoding="utf-8") as file:
            getcalog = file.read()
        parentcaurl_regex = re.search(r"CA Issuers - URI:\s*(.+)", getcalog, re.MULTILINE)
        if parentcaurl_regex:  # 確保找到了匹配 (parentcaurl_regex 不是 None)
            parentcaurl = parentcaurl_regex.group(1)  # 提取第一個捕獲組的內容
            # 現在 parentcaurl 是一個字串，你可以安全地使用它
            # 取父憑證
            target_cert = requests.get(parentcaurl)
            with open(cert_path + "/" + target_cert_filename, "wb") as file:
                file.write(target_cert.content)
        else:
            status = 1
    return target_cert_filename

def profile_generate(realm,name,short_name,type,mschapv2Stat,papStat,dns,url,mschapCert,papCert):

    """
    傳入設定檔所需要的參數，將會自動建立設定檔
    回傳設定檔檔名
    """
    if mschapv2Stat and papStat == True:
        source_file = geteduroam_template_both_filename
    elif papStat == True:
        source_file = geteduroam_template_ttls_pap_filename
    elif mschapv2Stat == True:
        source_file = geteduroam_template_peap_mschapv2_filename
    else:
        print("未知的錯誤")

    print()
    print(source_file,"\n成功複製到編輯暫存目錄！")

    # ----- 參數總整理 -----
    # / #Realm# / 電子郵件後綴 (realm)
    # / #Cert# / 憑證 (cert_content)
    # / #Domain# / DNS (dns_value)


    # 讀取檔案內容
    with open(template_path + "/" + source_file, "r", encoding="utf-8") as file:
        final_config = file.read()

    # 依次替換所有變數

    final_config = final_config.replace('#Realm#', realm)
    final_config = final_config.replace('#PEAP_MSCHAPv2Cert#', mschapCert)
    final_config = final_config.replace('#TTLS_PAPCert#', papCert)
    final_config = final_config.replace('#Domain#', dns)
    final_config = final_config.replace('#Name#', name + " 相容設定檔")
    final_config = final_config.replace('#Desc#', "設定檔由第三方生成，適用於帳號為 @" + realm + " 的帳號")
    final_config = final_config.replace('#Email#', "eduroamtw@googlegroups.com")
    final_config = final_config.replace('#URL#', url)
    final_config = final_config.replace('#Tel#', "NULL")

    # 將修改後的內容寫回檔案
    with open(profile_path + "/eduroam-eap-generic-" + short_name + ".eap-config", "w", encoding="utf-8") as file:
        file.write(final_config)

    profile_filename = realm + ".eap-config"

    return profile_filename

def database_log(realm,papstat,mschapv2stat,dns,pap_cert,mschapv2_cert,filename=log_path + "/" + log_filename):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow(["Time", "realm", "pap_stat", "mschapv2_stat", "dns",'cert_pap','cert_mschapv2'])
        writer.writerow([current_time, realm, pap_stat, mschapv2_stat, dns, pap_cert, mschapv2_cert])

if __name__ == "__main__":
    environment_test()
    realm_input = input("請輸入您想要產生設定檔的 realm (例如 mail.edu.tw): ")
    if not realm_input:
        print("您沒有輸入 realm，程式終止。")
    else:
        print(f"您輸入的 realm 是: {realm_input}")
        
        # spider_ustc_seesea(realm_input,source_id)
        # source id = 0: 中國科大 (https)
        # source id = 0: 西安科大 (http)
        realm,status_code = spider_ustc_seesea(realm_input,0)
        # realm,status_code = spider_ustc_seesea(realm_input,1)
        # realm,status_code = spider_local(realm_input)

        if status_code == 0: # 只有 status_code 為 0 (正常) 時才繼續分析
            dns, mschapv2_stat, mschapv2_cert, pap_stat, pap_cert = web_log_analyze(realm_input)

            database_log(realm,pap_stat,mschapv2_stat,dns,pap_cert,mschapv2_cert)

            if pap_stat == False and mschapv2_stat == False:
                exit()

            config_filename = profile_generate(
                realm=realm,
                name=realm, # 使用 realm 作為設定檔名稱
                short_name=realm,
                type="generic", # 設定 type 參數，雖然在此函式中未使用
                mschapv2Stat=mschapv2_stat,
                papStat=pap_stat,
                dns=dns,
                url="https://edur.isli.me/", # 設定預設 URL
                mschapCert=mschapv2_cert,
                papCert=pap_cert
            )

            if config_filename: # 檢查 config_filename 是否為 None
                print(f"\n設定檔 {config_filename} 產生成功！")
            else:
                print("\n設定檔產生失敗。")
        else:
            print("\n網頁下載失敗，請檢查網路連線或稍後再試。")