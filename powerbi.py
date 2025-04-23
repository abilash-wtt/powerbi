from flask import Flask, request, redirect, render_template_string, abort
from cryptography.fernet import Fernet

app = Flask(__name__)

# === CONFIGURATION ===
POWERBI_LINK = b"https://app.powerbi.com/view?r=eyJrIjoiZGRkZGJjOGItZTU0OC00NWY3LTg2ZDItOWM2NDM0NzU3ODAwIiwidCI6IjM4ZDc4NjJlLTRiMTAtNDM5Mi04MTFhLWM3OGFhNDlkOTE1OCJ9"
PASSWORD = "mysecret123"
ALLOWED_IPS = {"127.0.0.1", "10.15.6.141", "192.168.1.100", "localhost", "::1", "10.15.6.142"}
SECRET_KEY = Fernet.generate_key()  # Replace with your stored key
fernet = Fernet(SECRET_KEY)
ENCRYPTED_LINK = fernet.encrypt(POWERBI_LINK).decode()

# === HTML ===
HTML_FORM = """
<!DOCTYPE html>
<html>
<head><title>Secure Power BI</title></head>
<body>
    <h2>Enter Password to View Report</h2>
    <form method="POST" action="/view">
        <input type="password" name="password" placeholder="Enter password" required />
        <button type="submit">Access Report</button>
    </form>
</body>
</html>
"""

# === ROUTES ===
@app.before_request
def limit_remote_addr():
    ip = request.remote_addr
    if ip not in ALLOWED_IPS:
        print(f"Access attempt from {ip}. Forbidden.")
        abort(403)

@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_FORM)

@app.route("/view", methods=["POST"])
def view_report():
    password = request.form.get("password", "")
    if password == PASSWORD:
        try:
            decrypted_link = fernet.decrypt(ENCRYPTED_LINK.encode()).decode()
            return redirect(decrypted_link)
        except Exception as e:
            print("Decryption failed:", e)
            return "Internal error", 500
    return "Invalid password", 403

if __name__ == "__main__":
    print("🔐 Your secret key (save it!):", SECRET_KEY.decode())
    print("🔗 Encrypted Power BI link:", ENCRYPTED_LINK)
    print("🚀 App running on http://0.0.0.0:10000")
    app.run(host="0.0.0.0", port=10000, debug=True)
