import re

# 讀取 output.html 檔案內容
with open("output.html", "r", encoding="utf-8") as file:
    content = file.read()

# 使用正則表達式搜尋 "DNS:" 後的內容
match = re.search(r"DNS:\s*(.+)", content)

if match:
    dns_value = match.group(1).strip()  # 取得匹配到的內容並去除前後空白
    print("找到的 DNS:", dns_value)
else:
    print("未找到 DNS")