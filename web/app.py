from flask import Flask, request, send_file, render_template
import os

app = Flask(__name__)

OUTPUT_FOLDER = "outputs"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/process", methods=["POST"])
def process():
    text = request.form.get("text")
    if not text:
        return "沒有輸入內容", 400

    # Python 處理邏輯（範例：轉大寫）
    result = text.upper()

    return result
    # output_path = os.path.join(OUTPUT_FOLDER, "output.txt")
    # with open(output_path, "w", encoding="utf-8") as f:
    #     f.write(result)

    # return send_file(output_path, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)