# eduroam_profile_generater
- 從測試網站自動生成設定檔的工具
## 第一版
- 憑證使用 Mozilla CA Database 尋找
## 第二版
- Linux only
- 憑證從 log 中取出
- 將 PEAP-MSCHAPv2 與 TTLS-PAP 憑證分離
- 待修復
    - Line 47: Copy file issue 待修復
    - 憑證需要拆分至根憑證
    - 沒 fuzz 過，可能會有大量非預期輸入導致 Crach
    <!-- 作業要來不及寫了，先推 by chilin.h -->