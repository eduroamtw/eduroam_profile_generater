import requests

def get_certificates(cert_name):
    url = f"https://crt.sh/?q={cert_name}&output=json"
    response = requests.get(url)
    
    if response.status_code == 200:
        return response.json()
    else:
        return None

cert_name = input("輸入子憑證名稱: ") #"TWCA Secure SSL Certification Authority"
cert_data = get_certificates(cert_name)

if cert_data:
    for cert in cert_data[:1]:  # 只顯示前 5 筆結果
        print(f"Issuer Name: {cert.get('issuer_name', 'N/A')}")
else:
    print("未找到相關憑證")