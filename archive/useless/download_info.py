from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

# 設定瀏覽器
options = webdriver.ChromeOptions()
options.add_experimental_option("detach", True)  # 讓瀏覽器開啟後不自動關閉

# 開啟瀏覽器
driver = webdriver.Chrome(options=options)
driver.get("https://eduroam.ustc.edu.cn/")  # 這裡換成你的測試網址

# 等待網頁加載
time.sleep(2)

# 找到輸入框並填入帳號密碼
username_input = driver.find_element(By.NAME, "login")
password_input = driver.find_element(By.NAME, "password")

username_input.send_keys("ericchang030tw@mail.edu.tw")
password_input.send_keys("h20050405")
password_input.send_keys(Keys.RETURN)  # 模擬按下 Enter

# 等待結果
time.sleep(5)

# 抓取結果頁面（可以存檔 debug）
with open("result.html", "w", encoding="utf-8") as f:
    f.write(driver.page_source)

print("已存檔 result.html，可手動檢查")