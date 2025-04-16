import subprocess

# 設定帳號和密碼
account = "anonymous@mail.edu.tw"
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