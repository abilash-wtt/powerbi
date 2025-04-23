from flask import Flask, request, render_template_string, abort
from cryptography.fernet import Fernet

app = Flask(__name__)

# === CONFIGURATION ===

# ✅ Your actual Power BI public link (as bytes)
POWERBI_LINK = b"https://app.powerbi.com/view?r=eyJrIjoiZGRkZGJjOGItZTU0OC00NWY3LTg2ZDItOWM2NDM0NzU3ODAwIiwidCI6IjM4ZDc4NjJlLTRiMTAtNDM5Mi04MTFhLWM3OGFhNDlkOTE1OCJ9"

# 🔐 Set a strong password for access
PASSWORD = "mysecret123"

# 🌐 IPs allowed to access this report (add more as needed)
ALLOWED_IPS = {"127.0.0.1", "10.15.6.141", "192.168.1.100", "localhost", "::1", "10.15.6.142"}

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
            console.log("Sending password:", password); // Debugging log to check password

            fetch(`/decrypt?password=${encodeURIComponent(password)}`)
              .then(res => {
                  console.log("Response received:", res); // Debugging log to check the response
                  if (!res.ok) {
                      throw new Error("Failed to fetch the decrypted link.");
                  }
                  return res.text();
              })
              .then(link => {
                  console.log("Decrypted link received:", link); // Debugging log to show the decrypted link
                  if (link.startsWith("http")) {
                      document.getElementById("report").innerHTML = `
                        <iframe width="100%" height="800" src="${link}" frameborder="0" allowFullScreen="true"></iframe>
                      `;
                  } else {
                      throw new Error("Decryption failed or invalid link.");
                  }
              })
              .catch(err => {
                  console.error(err);
                  alert("Access denied or invalid password.");
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
        print(f"Access attempt from {ip}. Forbidden.")  # Log the failed IP attempt
        abort(403)  # Forbidden

@app.route("/")
def index():
    print("Rendering index page")  # Log when the index page is accessed
    return render_template_string(HTML_PAGE)

@app.route("/decrypt")
def decrypt():
    password = request.args.get("password", "")
    print(f"Password received: {password}")  # Log the received password

    if password == PASSWORD:
        print("Password correct. Decrypting link...")  # Log password success
        decrypted_link = fernet.decrypt(ENCRYPTED_LINK.encode()).decode()
        return decrypted_link
    else:
        print("Invalid password.")  # Log invalid password
        return "Invalid password", 403

if __name__ == "__main__":
    print("🔐 Your secret key (save it!):", SECRET_KEY.decode())
    print("🔗 Encrypted Power BI link:", ENCRYPTED_LINK)
    print("🚀 App running on http://0.0.0.0:10000")
    app.run(host="0.0.0.0", port=10000, debug=True)
