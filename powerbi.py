from flask import Flask, request, render_template_string, abort, redirect, Response
from cryptography.fernet import Fernet
import os

app = Flask(__name__)

# === CONFIGURATION ===

# Power BI link (as bytes)
POWERBI_LINK = b"https://app.powerbi.com/view?r=eyJrIjoiZGRkZGJjOGItZTU0OC00NWY3LTg2ZDItOWM2NDM0NzU3ODAwIiwidCI6IjM4ZDc4NjJlLTRiMTAtNDM5Mi04MTFhLWM3OGFhNDlkOTE1OCJ9"

# Password
PASSWORD = "mysecret123"

# Allowed IPs (used only in local/dev environment)
ALLOWED_IPS = {"127.0.0.1", "localhost", "::1", "10.15.6.141", "10.15.6.142"}

# Render environment detection
IS_RENDER = os.environ.get("RENDER", False)

# Generate and encrypt
SECRET_KEY = Fernet.generate_key()  # Replace this with saved key for persistence
fernet = Fernet(SECRET_KEY)
ENCRYPTED_LINK = fernet.encrypt(POWERBI_LINK).decode()

# === HTML PAGE ===
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Power BI</title>
</head>
<body>
    <h2>Enter Password to View Report</h2>
    <input type="password" id="password" placeholder="Enter password" />
    <button onclick="unlock()">Unlock</button>

    <div id="report" style="margin-top:20px;"></div>

    <script>
        function unlock() {
            const password = document.getElementById("password").value;
            fetch('/view_report', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'password=' + encodeURIComponent(password)
            })
            .then(res => res.text())
            .then(html => {
                if (html.startsWith("<iframe")) {
                    document.getElementById("report").innerHTML = html;
                } else {
                    alert("Invalid password or error.");
                }
            })
            .catch(err => alert("Error: " + err));
        }
    </script>
</body>
</html>
"""

# === ROUTES ===

@app.before_request
def limit_remote_addr():
    if IS_RENDER:
        return  # Skip IP filter in Render
    ip = request.remote_addr
    print(f"Incoming IP: {ip}")
    if ip not in ALLOWED_IPS:
        abort(403)

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

@app.route("/view_report", methods=["POST"])
def view_report():
    password = request.form.get("password", "")
    if password != PASSWORD:
        return "Invalid password", 403
    return '<iframe src="/proxy_report" width="100%" height="800" frameborder="0" allowfullscreen="true"></iframe>'

@app.route("/proxy_report")
def proxy_report():
    try:
        link = fernet.decrypt(ENCRYPTED_LINK.encode()).decode()
        return redirect(link)
    except Exception as e:
        return f"Error decrypting report: {e}", 500

if __name__ == "__main__":
    print("🔐 SECRET_KEY:", SECRET_KEY.decode())
    print("🔗 Encrypted Power BI link:", ENCRYPTED_LINK)
    print("🚀 Running on http://0.0.0.0:10000")
    app.run(host="0.0.0.0", port=10000, debug=True)
