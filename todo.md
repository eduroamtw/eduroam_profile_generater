
## Need to Fix


## Features
- [ ] os.system 處理邏輯跨平台
- [ ] 依賴套件 eapol / openssl 環境安裝盡量減少或用其他方式代替  
    - [ ] OpenSSL 預計使用 cryptography 替代，研究中  
    - [ ] eapol_test 應該無解
- [ ] 使用`uv build`和`uv publish`上傳至PyPI
- [ ] 修正 Authority Info Access 上游使用 p7b 格式產生的錯誤
- [ ] Domain 欄位從 eapol_test log 取得，改為解析憑證的 CN 值
