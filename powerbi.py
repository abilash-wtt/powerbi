from flask import Flask, request, render_template_string, abort
from cryptography.fernet import Fernet

app = Flask(__name__)

# === CONFIGURATION ===

# ✅ Your actual Power BI public link (as bytes)
POWERBI_LINK = b"https://app.powerbi.com/view?r=eyJrIjoiZGRkZGJjOGItZTU0OC00NWY3LTg2ZDItOWM2NDM0NzU3ODAwIiwidCI6IjM4ZDc4NjJlLTRiMTAtNDM5Mi04MTFhLWM3OGFhNDlkOTE1OCJ9"

# 🔐 Set a strong password for access
PASSWORD = "mysecret123"

# 🌐 IPs allowed to access this report (add more as needed)
ALLOWED_IPS = {"10.15.6.141", "192.168.1.100"}  # Replace with your IP(s)

# 🔑 Generate once and paste the same key here
SECRET_KEY = Fernet.generate_key()  # Only for demo. Replace with stored key if needed
fernet = Fernet(SECRET_KEY)

# 🔐 Encrypt the Power BI link once
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
            fetch(`/decrypt?password=${password}`)
              .then(res => res.text())
              .then(link => {
                  if (link.startsWith("http")) {
                      document.getElementById("report").innerHTML = `
                        <iframe width="100%" height="800" src="${link}" frameborder="0" allowFullScreen="true"></iframe>
                      `;
                  } else {
                      alert("Access denied or decryption failed.");
                  }
              });
        }
    </script>
</body>
</html>
"""


# === ROUTES ===

@app.before_request
def limit_remote_addr():
    ip = request.remote_addr
    if ip not in ALLOWED_IPS:
        abort(403)  # Forbidden


@app.route("/")
def index():
    return render_template_string(HTML_PAGE)


@app.route("/decrypt")
def decrypt():
    password = request.args.get("password", "")
    if password == PASSWORD:
        decrypted_link = fernet.decrypt(ENCRYPTED_LINK.encode()).decode()
        return decrypted_link
    else:
        return "Invalid password", 403


if __name__ == "__main__":
    print("🔐 Your secret key (save it!):", SECRET_KEY.decode())
    print("🔗 Encrypted Power BI link:", ENCRYPTED_LINK)
    print("🚀 App running on http://localhost:5000")
    app.run(debug=True)
