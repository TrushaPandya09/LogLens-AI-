from flask import Flask, render_template, request

from analyzer.log_analyzer import analyze_log

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


@app.route("/", methods=["GET", "POST"])
def index():
    analysis = None
    file_name = None
    error = None

    if request.method == "POST":
        uploaded_file = request.files.get("log_file")

        if uploaded_file is None or not uploaded_file.filename:
            error = "Choose a .log or .txt file to analyze."
        elif not uploaded_file.filename.lower().endswith((".log", ".txt")):
            error = "Only .log and .txt files are supported."
        else:
            try:
                log_text = uploaded_file.read().decode("utf-8")
            except UnicodeDecodeError:
                error = "The selected file must be a UTF-8 text file."
            else:
                analysis = analyze_log(log_text)
                file_name = uploaded_file.filename

    return render_template(
        "index.html",
        analysis=analysis,
        file_name=file_name,
        error=error,
    )


if __name__ == "__main__":
    app.run(debug=True)
