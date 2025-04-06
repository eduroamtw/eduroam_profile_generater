# eduroam_profile_generater

- 這是一個用於生成 eduroam 自動生成設定檔的工具。eduroam 是一個全球性的教育網路漫遊服務，讓教育機構的成員可以在其他參與機構使用無線網路。

## 第一版
- 憑證使用 Mozilla CA Database 尋找

## 第二版

- 憑證從 log 中取出
- 將 PEAP-MSCHAPv2 與 TTLS-PAP 憑證分離

## 功能特點

- 生成 eduroam 網路配置文件
- 支援多種認證方式
- 可自定義網路設定
- 支援不同作業系統的配置文件格式

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