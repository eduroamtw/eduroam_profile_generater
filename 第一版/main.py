import subprocess
import re
import shutil
import requests
import csv
import os

def get_certificates(cert_name):
    url = f"https://crt.sh/?q={cert_name}&output=json"
    response = requests.get(url)
    
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_certcontant(cacert, csv_file="cacert.csv"):
    with open(csv_file, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row["cert_name"] == cacert:
                return row["cert_content"]
    return None  # 如果找不到，返回 None

account = 'test@' + input("realm: ")
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

print("output.html fetch successfull")


# 讀取 output.html 檔案內容
with open("output.html", "r", encoding="utf-8") as file:
    content = file.read()

# 擷取 MSCHAP v2 和 PAP 區段
mschapv2_section = re.search(r"开始测试 EAP-PEAP MSCHAPv2(.*?)开始测试 EAP-TLS PAP", content, re.DOTALL)
pap_section = re.search(r"开始测试 EAP-TLS PAP(.*?)$", content, re.DOTALL)

# 檢查是否在對應區段內找到 "(handshake/certificate)"
mschapv2_found = "(handshake/certificate)" in (mschapv2_section.group(1) if mschapv2_section else "")
pap_found = "(handshake/certificate)" in (pap_section.group(1) if pap_section else "")

print("偵測開始...")

timeout = re.search(r"每10分钟允许30个请求，请稍后再来测试", content,re.DOTALL)

if timeout:
    print("請求過於頻繁，請稍後再試")
    exit()

# 判斷並輸出結果
if mschapv2_found and pap_found == True:
    print("MSCHAP v2 / PAP 憑證已拿取")
elif pap_found == True:
    print("PAP 憑證已拿取 / MSCHAP v2 憑證未拿取")
elif mschapv2_found == True:
    print("MSCHAP v2 憑證已拿取 / PAP 憑證未拿取")
else:
    print("MSCHAP v2 / PAP 憑證未拿取，未知的錯誤")
    exit()

print()


cert = re.search(r"CN=\s*(.+)", content)
print("Cert: \"",cert.group(1)[:-1].strip(),"\"", sep="")

match = re.search(r"DNS:\s*(.+)", content)

if match:
    dns_value = match.group(1).strip() 
    print("DNS: \"", dns_value, "\"", sep="")
else:
    print("未找到 DNS 資訊")
    exit()

realm = re.search(r"@\s*(.+)", account).group(1).strip()
print("Realm: \"",realm,"\"", sep="")

if mschapv2_found and pap_found == True:
    source_file = 'Template/eduroam-eap-generic-anonymous-Both.eap-config'
elif pap_found == True:
    source_file = 'Template/eduroam-eap-generic-anonymous-TTLS-PAP.eap-config'
elif mschapv2_found == True:
    source_file = 'Template/eduroam-eap-generic-anonymous-PEAP-MSCHAPv2.eap-config'
else:
    print("未知的錯誤")

destination_file = './config.eap-config'
shutil.copy(source_file, destination_file)
print()
print(source_file,"\n成功複製到編輯暫存目錄！")

print("\n正在從本地查詢憑證資料庫資訊...")

cert_content = get_certcontant(cert.group(1)[:-1].strip())

if cert_content:
    print("已在本地資料庫找到憑證")
else:
    print("未在本地資料庫找到該憑證\n")
    print("正在從 crt.sh 查詢根憑證資訊...")
    cert_name = cert.group(1)[:-1].strip()
    cert_data = get_certificates(cert_name)
    if cert_data:
        for cert in cert_data[:1]:
            # print(f"{cert.get('issuer_name', 'N/A')}")
            rootcert = re.search(r"CN=\s*(.+)", cert.get('issuer_name', 'N/A')).group(1).strip()
            print("Rootcert: ",rootcert)
    else:
        print("未找到相關根憑證")
        exit()
    print("\n正在依照根憑證名稱去查詢資料庫: ", end='')
    cert_content = get_certcontant(rootcert)
    if cert_content:
        print("已找到憑證")
    else:
        print("未找到該憑證")


# ----- 參數總整理 -----
# / #Realm# / 電子郵件後綴 (realm)
# / #Cert# / 憑證 (cert_content)
# / #Domain# / DNS (dns_value)


# 讀取檔案內容
with open('config.eap-config', 'r', encoding="utf-8") as file:
    final_config = file.read()

# 依次替換所有變數
final_config = final_config.replace('#Realm#', realm)
final_config = final_config.replace('#Cert#', cert_content)
final_config = final_config.replace('#Domain#', dns_value)
final_config = final_config.replace('#Name#', "auto_get_eduroam")
final_config = final_config.replace('#Email#', "eduroam@ichika.tw")
final_config = final_config.replace('#URL#', "https://www.ichika.tw")
final_config = final_config.replace('#Tel#', "886-3-890-6215")

# 將修改後的內容寫回檔案
with open('config.eap-config', 'w', encoding="utf-8") as file:
    file.write(final_config)

os.rename('./config.eap-config', f'./{realm}.eap-config')