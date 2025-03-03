# Line 46: Copy file issue 待修復
import subprocess
import re
import shutil
import requests
import csv
import os
import base64

def spider(realm):
    """
    傳入 realm (如 wifi.sso.edu.tw)
    回傳 realm,status_code
    status_code =
    0 正常
    -1 timeout
    """
    account = "anonymous@" + realm
    # account = "test@ndhu.edu.tw"
    password = "anonymous"

    # 構造 curl 指令
    curl_command = f"""
    curl --path-as-is -i -s -k -X 'GET' \
        -H 'Host: eduroam.ustc.edu.cn' \
        -H 'Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"' \
        -H 'Sec-Ch-Ua-Mobile: ?0' \
        -H 'Sec-Ch-Ua-Platform: "Windows"' \
        -H 'Accept-Language: zh-TW,zh;q=0.9' \
        -H 'Upgrade-Insecure-Requests: 1' \
        -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36' \
        -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' \
        -H 'Sec-Fetch-Site: none' \
        -H 'Sec-Fetch-Mode: navigate' \
        -H 'Sec-Fetch-User: ?1' \
        -H 'Sec-Fetch-Dest: document' \
        -H 'Accept-Encoding: gzip, deflate, br' \
        -H 'Priority: u=0, i' \
        -H 'Connection: keep-alive' \
        'https://eduroam.ustc.edu.cn/cgi-bin/eduroam-test.cgi?login={account}&password={password}' \
        -o "output.html"
    """

    # 執行 curl 指令
    subprocess.run(curl_command, shell=True)
    print(account + " 下載完畢")
    os.system(f"cp ./output.html ./archive/html/{realm}.html")

    # 讀取 output.html 檔案內容
    with open("output.html", "r", encoding="utf-8") as file:
        content = file.read()

    timeout = re.search(r"每10分钟允许30个请求，请稍后再来测试", content,re.DOTALL)

    if timeout:
        print("請求過於頻繁，請稍後再試")
        status_code = -1
    else:
        status_code = 0

    return realm,status_code

def log_analyze(realm):
    """
    傳入 realm (如 mail.edu.tw)
    回傳 DNS,PEAP-MSCHAPv2 Status,PEAP-MSCHAPv2 Cert (Base64),TTLS-PAP Status,TTLS-PAP Cert (Base64)
    """
    logfile = realm + ".html" # html 檔案位置
    with open(logfile, "r", encoding="utf-8") as file:
        content = file.read()
    # 讀取 DNS
    match = re.search(r"DNS:\s*(.+)", content)

    if match:
        dns_value = match.group(1).strip() 
        print("DNS: \"", dns_value, "\"", sep="")
    else:
        dns_value = "NULL"
        print("未找到 DNS 資訊")
    # 擷取 MSCHAP v2 和 PAP 區段
    mschapv2_section = re.search(r"开始测试 EAP-PEAP MSCHAPv2(.*?)开始测试 EAP-TLS PAP", content, re.DOTALL)
    pap_section = re.search(r"开始测试 EAP-TLS PAP(.*?)$", content, re.DOTALL)

    # 檢查是否在對應區段內找到 "(handshake/certificate)"
    mschapv2_found = "(handshake/certificate)" in (mschapv2_section.group(1) if mschapv2_section else "")
    pap_found = "(handshake/certificate)" in (pap_section.group(1) if pap_section else "")

    print("偵測開始...")

    # 判斷並輸出結果
    if mschapv2_found and pap_found == True:
        print("MSCHAP v2 / PAP 憑證已拿取")
        c = export_cert(realm,"PEAP-MSCHAPv2",mschapv2_section.group(1))
        e = export_cert(realm,"TTLS-PAP",pap_section.group(1))
    elif pap_found == True:
        print("PAP 憑證已拿取 / MSCHAP v2 憑證未拿取")
        c = "NULL"
        e = export_cert(realm,"TTLS-PAP",pap_section.group(1))
    elif mschapv2_found == True:
        print("MSCHAP v2 憑證已拿取 / PAP 憑證未拿取")
        c = export_cert(realm,"PEAP-MSCHAPv2",mschapv2_section.group(1))
        e = "NULL"
    else:
        print("MSCHAP v2 / PAP 憑證未拿取，未知的錯誤")
        c = "NULL"
        e = "NULL"
    """
    a=DNS
    b=PEAP-MSCHAPv2 Status
    c=PEAP-MSCHAPv2 Cert (Base64)
    d=TTLS-PAP Status
    e=TTLS-PAP Cert (Base64)
    """
    a=dns_value
    b=mschapv2_found
    d=pap_found
    return a,b,c,d,e
    


def export_cert(filename,method,cert_content): # 傳入整段 log
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
    filename_der = filename + "-" + method + "-DER.crt"
    with open(filename_der, 'wb') as file:
        file.write(cert_der)
    cert_b64 = base64.b64encode(cert_der)
    base64_cert = cert_b64.decode("utf-8")
    return base64_cert
    # 將修改後的內容寫回檔案

def profile_generate(realm,name,type,mschapv2Stat,papStat,dns,url,mschapCert,papCert):
    """
    傳入設定檔所需要的參數，將會自動建立設定檔
    回傳設定檔檔名
    """

    if mschapv2Stat and papStat == True:
        source_file = 'Template/eduroam-eap-generic-anonymous-Both.eap-config'
    elif papStat == True:
        source_file = 'Template/eduroam-eap-generic-anonymous-TTLS-PAP.eap-config'
    elif mschapv2Stat == True:
        source_file = 'Template/eduroam-eap-generic-anonymous-PEAP-MSCHAPv2.eap-config'
    else:
        print("未知的錯誤")

    destination_file = './config.eap-config'
    shutil.copy(source_file, destination_file)
    print()
    print(source_file,"\n成功複製到編輯暫存目錄！")

    # ----- 參數總整理 -----
    # / #Realm# / 電子郵件後綴 (realm)
    # / #Cert# / 憑證 (cert_content)
    # / #Domain# / DNS (dns_value)


    # 讀取檔案內容
    with open('config.eap-config', 'r', encoding="utf-8") as file:
        final_config = file.read()

    # 依次替換所有變數

    final_config = final_config.replace('#Realm#', realm)
    final_config = final_config.replace('#PEAP_MSCHAPv2Cert#', mschapCert)
    final_config = final_config.replace('#TTLS_PAPCert#', papCert)
    final_config = final_config.replace('#Domain#', dns)
    final_config = final_config.replace('#Name#', name + " 相容設定檔")
    final_config = final_config.replace('#Desc#', "設定檔由第三方生成，適用於帳號為 @" + realm + "的帳號")
    final_config = final_config.replace('#Email#', "eduroamtw@googlegroups.com")
    final_config = final_config.replace('#URL#', url)
    final_config = final_config.replace('#Tel#', "886-3-890-6215")

    # 將修改後的內容寫回檔案
    with open('config.eap-config', 'w', encoding="utf-8") as file:
        file.write(final_config)

    os.rename('./config.eap-config', f'./{realm}.eap-config')

    rt=realm + ".eap-config"

    return rt

if __name__ == "__main__":
    realm_input = input("請輸入您想要產生設定檔的 realm (例如 mail.edu.tw): ")
    if not realm_input:
        print("您沒有輸入 realm，程式終止。")
    else:
        print(f"您輸入的 realm 是: {realm_input}")

        realm,status_code = spider(realm_input)

        if status_code == 0: # 只有 status_code 為 0 (正常) 時才繼續分析
            dns, mschapv2_stat, mschapv2_cert, pap_stat, pap_cert = log_analyze(realm_input)

            config_filename = profile_generate(
                realm=realm,
                name=realm, # 使用 realm 作為設定檔名稱
                type="generic", # 設定 type 參數，雖然在此函式中未使用
                mschapv2Stat=mschapv2_stat,
                papStat=pap_stat,
                dns=dns,
                url="https://www.eduroam.tw/", # 設定預設 URL
                mschapCert=mschapv2_cert,
                papCert=pap_cert
            )

            if config_filename: # 檢查 config_filename 是否為 None
                print(f"\n設定檔 {config_filename} 產生成功！")
            else:
                print("\n設定檔產生失敗。")
        else:
            print("\n網頁下載失敗，請檢查網路連線或稍後再試。")