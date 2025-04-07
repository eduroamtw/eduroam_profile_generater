# eduroam_profile_generater
這是一個讓組織管理員或終端使用者可以輕易生成 eduroam WiFi 設定檔的工具，該格式相容於 geteduroam 與 eduroam CAT 程式。<br>
eduroam 是一個全球性的教育網路漫遊服務，讓教育機構的成員可以在其他參與機構使用無線網路。<br>
使用此程式，需要您提供登入帳號 的 Realm (帳號 @ 後的資訊)，不需要真實帳號密碼。

## 功能特點
- 多種資訊來源
    - 一般使用者：於公開測試網站中直接取得 log 分析
    - iDP 所有者：直連單位內的 RADIUS Server
- 生成多種檔案
    - 設定檔
    - 伺服器 CA 憑證
- 認證方式
    - EAP-PEAP-MSCHAPv2
    - EAP-TTLS-PAP

## 系統需求

- Python 3.8 或更高版本
- pip（Python 套件管理器）

## 安裝步驟

1. git clone：
```bash
git clone https://github.com/eduroamtw/eduroam_profile_generater/tree/version_2
cd eduroam_profile_generater
```

2. 安裝依賴套件：
```bash
pip install -r requirements.txt
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

- 請確保生成的配置文件符合目標機構的安全要求
- 建議在測試環境中先進行測試
- 請妥善保管生成的配置文件

## 貢獻指南

歡迎提交 Issue 或 Pull Request 來協助改進此專案。

## 聯絡方式

如有任何問題或建議，請透過以下方式聯絡：

- 提交 Issue
- 發送 Email 至：[eduroamtw@googlegroups.com]