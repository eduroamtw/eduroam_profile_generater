# eduroam_profile_generater
這是一個讓組織管理員或終端使用者可以輕易生成 eduroam WiFi 設定檔的工具，該設定檔相容於 geteduroam 與 eduroam CAT 程式。<br>
eduroam 是一個全球性的教育網路漫遊服務，讓教育機構的成員可以在其他參與機構使用無線網路。<br>
使用此程式，需要您提供登入帳號 的 Realm (帳號 @ 後的資訊)，不需要真實帳號密碼。<br>
如果您是一般使用者，我們更推薦您使用我們的 Colab 版本，省去您安裝環境的時間。<br>
Colab 版本：[GitHub](https://github.com/eduroamtw/eduroam_profile_generater_colab) [Colab](https://colab.research.google.com/github/eduroamtw/eduroam_profile_generater_colab/blob/main/eduroam_profile_generater_colab.ipynb)<br>

## 功能特點
- 支援多個認證伺服器來源
    - 公開測試站點
    - RADIUS Server (需要 eapol_test，目前僅 Linux 可用，Windows 建議使用 WSL)
- 憑證處理自動化
    - 從 log 中的 OpenSSL hex dump 直接撈取憑證，不依賴其他第三方服務
    - 撈取憑證後，自動追溯該憑證 Root CA
- 多種檔案同時產出
    - 設定檔
    - RADIUS Server Certificate
    - RADIUS Server CA Certificate
- 支援認證方式
    - EAP-PEAP-MSCHAPv2
    - EAP-TTLS-PAP

## 系統需求
- Python 3.8 或更高版本（可執行 `python -V` 確認版本）
- pip（可執行 `pip -V` 確認是否運作正常）
- OpenSSL (可執行 `openssl -v` 確認是否運作正常)

## 安裝步驟
1. 複製儲存庫：
```bash
git clone https://github.com/eduroamtw/eduroam_profile_generater.git
cd eduroam_profile_generater
```

2. 安裝依賴套件：
```bash
virtualenv edurprofgen
source edurprofgen/bin/activate
python3 -m pip install -r requirements.txt
```

## 使用方法

1. 執行程式：
```bash
python main.py
```

- 在某些系統上可能需要

```bash
python3 main.py
```

## 注意事項

1. 此程式並未執行帳號有效性測試，僅根據憑證回傳有無判斷 RADIUS 是否接受認證。在公開散布設定檔前，請進行人工測試複驗，確認是否能正常使用。
2. 本程式主要為分析 log 檔案，並提取所需資訊，製成設定檔。我們不對帳號測試網站回傳的資料做任何擔保，如果你是 eduroam SP 或 iDP，建議優先使用貴單位的 RADIUS Server。
3. 如貴單位已經支援官方 eduroam CAT 服務，則建議使用官方服務 [Link](https://cat.eduroam.org/)。

## 貢獻指南

歡迎開啟 Issue 或 Pull Request 來協助改進此專案。

## 聯絡方式

如果有任何問題或建議，歡迎透過以下方式聯絡我們：

- 開啟 Issue
- 傳送 Email 至：[eduroamtw@googlegroups.com](mailto:eduroamtw@googlegroups.com)