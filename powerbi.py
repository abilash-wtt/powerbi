from flask import Flask, request, render_template_string, abort
from cryptography.fernet import Fernet

app = Flask(__name__)

# === CONFIGURATION ===

# Your actual Power BI public link (as bytes)
POWERBI_LINK = b"https://app.powerbi.com/view?r=eyJrIjoiZGRkZGJjOGItZTU0OC00NWY3LTg2ZDItOWM2NDM0NzU3ODAwIiwidCI6IjM4ZDc4NjJlLTRiMTAtNDM5Mi04MTFhLWM3OGFhNDlkOTE1OCJ9"

# Set a strong password for access
PASSWORD = "mysecret123"

# IPs allowed to access this report (optional, works locally and with proxy-aware cloud hosts)
ALLOWED_IPS = {
    "127.0.0.1", "localhost", "::1",  # Localhost access
    "10.15.6.141", "10.15.6.142",     # Local IPs (add your Render IP if needed)
    # You can add more if needed
}

# Generate once and paste the same key here for consistent encryption
SECRET_KEY = Fernet.generate_key()  # Replace with your stored key for production
fernet = Fernet(SECRET_KEY)
ENCRYPTED_LINK = fernet.encrypt(POWERBI_LINK).decode()


# === HTML PAGE ===

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Power BI Report</title>
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            })
            .then(res => res.ok ? res.text() : Promise.reject("Access denied"))
            .then(html => {
                document.getElementById("report").innerHTML = html;
            })
            .catch(err => {
                alert(err);
            });
        }
    </script>
</body>
</html>
"""


# === IP Filtering (Optional, works with Render) ===

@app.before_request
def limit_remote_addr():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    print(f"Client IP: {ip}")
    if ip not in ALLOWED_IPS:
        abort(403)


# === Routes ===

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)


@app.route("/view_report", methods=["POST"])
def view_report():
    data = request.get_json()
    password = data.get("password", "")

    if password == PASSWORD:
        decrypted_link = fernet.decrypt(ENCRYPTED_LINK.encode()).decode()
        iframe = f"""
        <iframe width="100%" height="800" src="{decrypted_link}"
                frameborder="0" allowFullScreen="true"></iframe>
        """
        return iframe
    else:
        return "Invalid password", 403


# === Main App Run ===

if __name__ == "__main__":
    print("🔐 Your secret key (save it!):", SECRET_KEY.decode())
    print("🔗 Encrypted Power BI link:", ENCRYPTED_LINK)
    app.run(host="0.0.0.0", port=10000, debug=True)
