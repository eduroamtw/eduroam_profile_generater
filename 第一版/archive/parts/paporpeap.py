import re

# 讀取 output.html 檔案內容
with open("output.html", "r", encoding="utf-8") as file:
    content = file.read()

# 使用正則表達式分割不同的測試區間
mschapv2_section = re.search(r"开始测试 EAP-PEAP MSCHAPv2(.*?)开始测试 EAP-TLS PAP", content, re.DOTALL)
pap_section = re.search(r"开始测试 EAP-TLS PAP(.*?)$", content, re.DOTALL)

# 檢查是否在對應區段內找到 "(handshake/certificate)"
mschapv2_found = "(handshake/certificate)" in (mschapv2_section.group(1) if mschapv2_section else "")
pap_found = "(handshake/certificate)" in (pap_section.group(1) if pap_section else "")

print(mschapv2_found)
print(pap_found)
# 判斷並輸出結果
if mschapv2_found and pap_found == True:
    print("MSCHAP v2 / PAP 憑證已拿取")
elif pap_found == True:
    print("PAP 憑證已拿取 / MSCHAP v2 憑證未拿取")
elif mschapv2_found == True:
    print("MSCHAP v2 憑證已拿取 / PAP 憑證未拿取")
else:
    print("MSCHAP v2 / PAP 憑證未拿取")