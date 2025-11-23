# 重構後的架構說明

## 概述

此專案已重構為採用 **Clean Architecture** 設計模式，提升程式碼的可維護性、可測試性和可擴展性。

## 架構層級

```
┌─────────────────────────────────────┐
│        Presentation Layer           │
│   (main.py, application.py)         │
├─────────────────────────────────────┤
│         Service Layer               │
│  (authentication, certificate,      │
│   profile, logging services)        │
├─────────────────────────────────────┤
│         Domain Layer                │
│  (models, business rules,           │
│   exceptions)                       │
├─────────────────────────────────────┤
│      Infrastructure Layer           │
│  (file repository, command          │
│   executor)                         │
└─────────────────────────────────────┘
```

## 目錄結構

```
src/
├── domain/                  # 領域層
│   ├── models.py           # 領域模型
│   └── exceptions.py       # 自訂例外
├── services/               # 服務層
│   ├── authentication_service.py
│   ├── certificate_service.py
│   ├── profile_service.py
│   └── logging_service.py
├── infrastructure/         # 基礎設施層
│   ├── file_repository.py
│   └── command_executor.py
├── application.py          # 應用程式編排
└── config.py              # 配置管理
```

## 核心組件

### 1. Domain Layer (領域層)

**領域模型 (models.py)**
- `Realm`: 代表 eduroam realm (網域)
- `Certificate`: 代表 TLS 憑證
- `AuthenticationResult`: 認證測試結果
- `ProfileConfig`: 設定檔配置
- `AuthMethod`: 認證方法枚舉
- `TestServer`: 測試伺服器枚舉

**例外處理 (exceptions.py)**
- `EduroamError`: 基礎例外類別
- `AuthenticationError`: 認證失敗
- `CertificateError`: 憑證處理失敗
- `ProfileGenerationError`: 設定檔產生失敗
- `RateLimitError`: 超過請求限制
- `NetworkError`: 網路請求失敗

### 2. Service Layer (服務層)

**CertificateService**
- 從 log 提取憑證
- 處理憑證格式轉換 (DER ↔ PEM)
- 追溯 Root CA 憑證鏈

**AuthenticationService**
- 測試 eduroam 認證
- 解析認證 log
- 提取 DNS 資訊
- 整合憑證處理

**ProfileService**
- 選擇適當的模板
- 替換模板變數
- 產生設定檔

**LoggingService**
- 記錄認證結果到 CSV
- 初始化 log 檔案

### 3. Infrastructure Layer (基礎設施層)

**FileRepository**
- 抽象化檔案操作
- 支援文字/二進位讀寫
- JSON/CSV 處理
- 目錄管理

**CommandExecutor**
- 安全執行 shell 命令
- 使用 subprocess 取代 os.system()
- 結構化命令結果

### 4. Application Layer (應用層)

**EduroamProfileGenerator**
- 協調所有服務
- 處理使用者互動
- 錯誤處理和顯示
- 依賴注入管理

## 改進點

### ✅ 分離關注點
- 每個類別/函數只負責一件事
- 清楚的職責劃分

### ✅ 依賴注入
- 服務之間透過建構函數注入依賴
- 易於測試和替換實作

### ✅ 型別安全
- 使用 dataclass 和型別提示
- 不可變領域模型 (frozen=True)

### ✅ 錯誤處理
- 自訂例外類別
- 清楚的錯誤訊息
- 適當的錯誤傳播

### ✅ 安全性
- 使用 subprocess 取代 os.system()
- 命令參數化執行
- 防止命令注入

### ✅ 可測試性
- 抽象介面 (ABC)
- 依賴注入
- 無隱藏副作用

### ✅ 可維護性
- 清楚的程式碼結構
- 單一職責原則
- 易於理解和修改

## 向後相容性

舊的程式碼檔案已重新命名為 `*_old.py`：
- `app.py` → `app_old.py`
- `auth.py` → `auth_old.py`
- `profile.py` → `profile_old.py`
- `utils.py` → `utils_old.py`

## 使用方式

```bash
# 執行主程式
uv run gen

# 或直接執行
python main.py
```

## 未來擴展

由於採用 Clean Architecture，未來可以輕鬆：
- 新增單元測試
- 支援更多認證方法
- 新增 CLI 參數支援
- 實作 GUI 介面
- 支援批次處理
- 新增配置檔案支援
