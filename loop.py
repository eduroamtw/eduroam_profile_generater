import subprocess
import re
import time
import sys

def run_script(input_text):
    result = subprocess.run(["python", "main2.py"], input=input_text, text=True, capture_output=True)
    return result.stdout

with open("raw_input.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

with open("output.txt", "w", encoding="utf-8") as output_file:  # 以寫入模式開啟檔案
    for line in lines:
        line = line.strip()
        if not line:
            continue

        while True:  # 這裡用 while 迴圈重試直到成功
            output = run_script(line)
            print(output, end="")  # 印出結果到終端機
            print("-" * 40)  # 印出分隔線到終端機
            output_file.write(output + "")  # 寫入輸出到檔案
            output_file.write("-" * 40 + "\n")  # 寫入分隔線
            output_file.flush()  # 立即寫入檔案，避免當機時資料丟失
            
            if "請求過於頻繁，請稍後再試" in output:
                for remaining in range(60, 0, -1):
                    sys.stdout.write(f"\r{remaining:2d} seconds remaining.")
                    sys.stdout.flush()
                    time.sleep(1)
                print("\nRetrying...\n")
            else:
                break  # 若執行成功，跳出重試迴圈