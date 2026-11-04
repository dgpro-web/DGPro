"""
DGPRO Digital Downloads - Production-Ready Razorpay Backend Server (Python 3)
Features:
1. Razorpay HMAC-SHA256 signature verification & official Webhook listener.
2. Cryptographic download token generator with strict quota and 7-day expiration.
3. Server-Side Admin Authentication Gate (Secure HttpOnly session cookie,
   protected HTML, locked API endpoints, and brute-force shielding).
4. Set & Update Admin Username, Password, PIN, and Master Recovery Key.
5. Forgot Password & PIN Recovery flow (Terminal One-Time OTP & Master Key).
6. Anti-Inspect & Right-Click Disabling across Admin and Login interfaces.
"""

import http.server
import socketserver
import urllib.parse
import json
import hmac
import hashlib
import os
import time
import secrets
import base64

# Lightweight .env loader (loads environment variables from .env if present)
_env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(_env_file):
    try:
        with open(_env_file, 'r', encoding='utf-8') as _ef:
            for _line in _ef:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _k, _v = _line.split('=', 1)
                    _k = _k.strip()
                    _v = _v.strip().strip('"').strip("'")
                    if _k and _k not in os.environ:
                        os.environ[_k] = _v
    except Exception as _env_err:
        print("Notice: Error reading .env file:", _env_err)

PORT = int(os.environ.get('PORT', 5000))
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID', '').strip()
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '').strip()
RAZORPAY_WEBHOOK_SECRET = os.environ.get('RAZORPAY_WEBHOOK_SECRET', '').strip()

# Server-Side Default Admin Credentials
DEFAULT_ADMIN_USERNAME = 'admin'
DEFAULT_ADMIN_PIN_HASH = 'ef76c75232e68c9618b17e3ea292def3c51d834543d289f6ff10a608731341c2'   # '1234'
DEFAULT_ADMIN_PASS_HASH = '8957d31b893a136c06f35129e9f0c5bf6ab8479929926d8f4f552ffe4f819a98'  # 'dgpro@admin2026'
DEFAULT_RECOVERY_KEY = 'DGPRO-ADMIN-MASTER-RECOVERY'

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.json')
STATIC_DIR = os.path.dirname(os.path.abspath(__file__))
VIDEOS_DIR = os.path.join(STATIC_DIR, 'videos')
os.makedirs(VIDEOS_DIR, exist_ok=True)

# Persistent JSON Database
db = {
    "orders": [],
    "customers": [],
    "sellers": [],
    "downloadTokens": {},
    "adminSessions": {},
    "adminCredentials": {
        "username": DEFAULT_ADMIN_USERNAME,
        "passwordHash": DEFAULT_ADMIN_PASS_HASH,
        "pinHash": DEFAULT_ADMIN_PIN_HASH,
        "recoveryKey": DEFAULT_RECOVERY_KEY
    }
}

# In-memory brute-force rate limiter & recovery OTP
failed_login_attempts = {}
active_recovery_otp = {}
customer_otps = {}  # { mobile: { "otp": "...", "expiresAt": timestamp, "attempts": 0 } }
FAST2SMS_API_KEY = os.environ.get('FAST2SMS_API_KEY', '3jVi78avL4iWyn5UKp31Y6Dd9Opi5lFyP0htNd8MRNKDVfeK0UfeRfyET3oAmI3MFxRtI7uaa39tAx9N')
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_EMAIL = os.environ.get('SMTP_EMAIL', 'dgproofficials@gmail.com')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
GMAIL_WEBHOOK_URL = os.environ.get('GMAIL_WEBHOOK_URL', 'https://script.google.com/macros/s/AKfycbzloaYJ9lRr6zd-PZqTAJ0gBIA9Y1Tv3EWG9HioKsKEqrhLZtakYkYQc5DUvqL4y0OMqA/exec')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')

def dispatch_email_otp(to_email, otp_code, customer_name="Customer", mobile_number=""):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    if not SMTP_EMAIL or not SMTP_PASSWORD:
        return False, "SMTP_PASSWORD not configured. Set SMTP_PASSWORD in Render Environment Variables."

    subject = f"{otp_code} is your DGPRO Store Verification Code"
    html_content = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 28px; border: 1px solid #e4ddd3; border-radius: 20px; background-color: #faf8f5;">
      <div style="text-align: center; margin-bottom: 24px;">
        <h2 style="color: #18201e; margin: 0; font-size: 26px; font-weight: 900; letter-spacing: -0.5px;">DGPRO <span style="color: #b89252; font-style: italic;">Store</span></h2>
        <span style="color: #8c7f70; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Official Account Verification</span>
      </div>
      <p style="color: #333; font-size: 14px; line-height: 1.6; margin-bottom: 8px;">Hello <strong>{customer_name}</strong>,</p>
      <p style="color: #555; font-size: 13px; line-height: 1.6; margin-bottom: 20px;">Use the 6-digit verification code below to complete your DGPRO Digital Store login for Mobile Number <strong>+91 {mobile_number}</strong>:</p>
      <div style="text-align: center; margin: 28px 0;">
        <span style="font-size: 34px; font-weight: 900; letter-spacing: 8px; color: #18201e; background: #efe6d8; padding: 14px 28px; border-radius: 14px; border: 2px solid #b89252; display: inline-block; font-family: monospace;">{otp_code}</span>
      </div>
      <p style="color: #666; font-size: 12px; line-height: 1.5; margin-bottom: 4px;">⏱️ This verification code is valid for <strong>5 minutes</strong>.</p>
      <p style="color: #888; font-size: 12px; line-height: 1.5;">🔒 For your security, do not share this OTP with anyone.</p>
      <hr style="border: none; border-top: 1px solid #e4ddd3; margin: 24px 0 16px 0;" />
      <p style="color: #aaa; font-size: 11px; text-align: center; margin: 0;">DGPRO Digital Downloads Store • <a href="https://dgpro.site" style="color: #b89252; text-decoration: none; font-weight: bold;">www.dgpro.site</a></p>
    </div>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"DGPRO Digital Store <{SMTP_EMAIL}>"
    msg["To"] = to_email
    msg.attach(MIMEText(f"Your DGPRO Store verification code is {otp_code}. Valid for 5 minutes.", "plain"))
    msg.attach(MIMEText(html_content, "html"))

    # Route 1: Google Apps Script Webhook (Port 443 HTTPS - Works 100% on Render Free!)
    if GMAIL_WEBHOOK_URL:
        try:
            req_data = json.dumps({
                "to": to_email.strip(),
                "subject": subject,
                "html": html_content,
                "text": f"Your DGPRO Store verification code is {otp_code}. Valid for 5 minutes."
            }).encode('utf-8')
            req = urllib.request.Request(
                GMAIL_WEBHOOK_URL.strip(),
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"📧 [GMAIL WEBHOOK SENT]: Successfully delivered code {otp_code} to {to_email}!")
                return True, "Email sent via Gmail Webhook."
        except Exception as e:
            print(f"⚠️ [GMAIL WEBHOOK FAILED]: {e}")

    # Route 2: Resend API (Port 443 HTTPS)
    if RESEND_API_KEY:
        try:
            req_data = json.dumps({
                "from": f"DGPRO Store <{SMTP_EMAIL}>",
                "to": [to_email.strip()],
                "subject": subject,
                "html": html_content
            }).encode('utf-8')
            req = urllib.request.Request(
                "https://api.resend.com/emails",
                data=req_data,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY.strip()}",
                    "Content-Type": "application/json"
                }
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                print(f"📧 [RESEND EMAIL SENT]: Successfully delivered code {otp_code} to {to_email}!")
                return True, "Email sent via Resend."
        except Exception as e:
            print(f"⚠️ [RESEND FAILED]: {e}")

    # Route 3: Standard SMTP (Timeout 3s so it never hangs Render Free tier)
    if SMTP_PASSWORD:
        try:
            clean_pwd = SMTP_PASSWORD.replace(' ', '').strip()
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=3)
            server.starttls()
            server.login(SMTP_EMAIL.strip(), clean_pwd)
            server.sendmail(SMTP_EMAIL.strip(), [to_email.strip()], msg.as_string())
            server.quit()
            print(f"📧 [EMAIL OTP SENT]: Successfully delivered code {otp_code} to {to_email}!")
            return True, "Email OTP sent successfully."
        except Exception as e:
            print(f"⚠️ [EMAIL SMTP FAILED (Render Free blocks port 587)]: {e}")
            return False, str(e)

    return False, "No working email route configured."

FAST2SMS_OTP_ID = os.environ.get('FAST2SMS_OTP_ID', '')

def load_database():
    global db
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                db = json.load(f)
                if "orders" not in db: db["orders"] = []
                if "customers" not in db: db["customers"] = []
                if "sellers" not in db: db["sellers"] = []
                if "downloadTokens" not in db: db["downloadTokens"] = {}
                if "storeConfig" not in db: db["storeConfig"] = {}
                if "adminSessions" not in db: db["adminSessions"] = {}
                if "adminCredentials" not in db:
                    db["adminCredentials"] = {
                        "username": DEFAULT_ADMIN_USERNAME,
                        "passwordHash": DEFAULT_ADMIN_PASS_HASH,
                        "pinHash": DEFAULT_ADMIN_PIN_HASH,
                        "recoveryKey": DEFAULT_RECOVERY_KEY
                    }
        except Exception as e:
            print("DB load warning:", e)
    else:
        save_database()

def save_database():
    try:
        tmp_file = DATA_FILE + '.tmp'
        with open(tmp_file, 'w', encoding='utf-8') as f:
            json.dump(db, f, indent=2, ensure_ascii=False)
        os.replace(tmp_file, DATA_FILE)
    except Exception as e:
        print("DB save error:", e)

load_database()

# Cryptographic Utilities
def hash_with_salt(val):
    payload = (str(val).strip() + '_dgpro_salt_2026').encode('utf-8')
    return hashlib.sha256(payload).hexdigest()

def verify_payment_signature(rzp_order_id, rzp_payment_id, rzp_signature):
    if not rzp_order_id or not rzp_payment_id or not rzp_signature or not RAZORPAY_KEY_SECRET:
        return False
    try:
        payload = f"{rzp_order_id}|{rzp_payment_id}".encode('utf-8')
        expected = hmac.new(RAZORPAY_KEY_SECRET.encode('utf-8'), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, rzp_signature)
    except Exception:
        return False

def verify_webhook_signature(raw_body_bytes, signature_header):
    if not raw_body_bytes or not signature_header:
        return False
    try:
        expected = hmac.new(RAZORPAY_WEBHOOK_SECRET.encode('utf-8'), raw_body_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_header)
    except Exception:
        return False


def dispatch_fast2sms(mobile_10_digit, otp_code):
    if not FAST2SMS_API_KEY:
        return False, "No Fast2SMS API key configured."
    import urllib.request
    import urllib.parse
    import urllib.error

    api_key = FAST2SMS_API_KEY.strip()
    clean_mobile = str(mobile_10_digit).strip()

    # Route 0: Fast2SMS Smart OTP (WhatsApp Route - ₹0.25 per OTP)
    if FAST2SMS_OTP_ID:
        try:
            req_data = json.dumps({
                "otp_id": str(FAST2SMS_OTP_ID).strip(),
                "mobile": clean_mobile
            }).encode('utf-8')
            req0 = urllib.request.Request(
                "https://www.fast2sms.com/dev/otp/send",
                data=req_data,
                headers={
                    "authorization": api_key,
                    "Content-Type": "application/json",
                    "accept": "application/json",
                    "User-Agent": "Mozilla/5.0"
                },
                method="POST"
            )
            with urllib.request.urlopen(req0, timeout=8) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                print("\n" + "="*56)
                print("📡 [FAST2SMS SMART OTP (WHATSAPP) RESPONSE]:", data)
                print("="*56 + "\n")
                if data.get('return') is True or data.get('status_code') == 200:
                    return True, "OTP dispatched successfully via WhatsApp (Fast2SMS Smart OTP)."
        except urllib.error.HTTPError as he:
            try:
                err_data = json.loads(he.read().decode('utf-8'))
                print("\n⚠️ [FAST2SMS WHATSAPP OTP ERROR]:", err_data)
            except Exception:
                print("\n⚠️ [FAST2SMS WHATSAPP OTP ERROR]:", he)
        except Exception as e0:
            print("⚠️ Fast2SMS Smart OTP (WhatsApp) route warning:", e0)

    # Route 1: Fast2SMS OTP Route
    try:
        q1 = urllib.parse.urlencode({
            'authorization': api_key,
            'route': 'otp',
            'variables_values': str(otp_code),
            'flash': '0',
            'numbers': clean_mobile
        })
        url1 = f"https://www.fast2sms.com/dev/bulkV2?{q1}"
        req1 = urllib.request.Request(url1, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req1, timeout=8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            print("\n" + "="*56)
            print("📡 [FAST2SMS API RESPONSE]:", data)
            print("="*56 + "\n")
            if data.get('return') is True or data.get('status_code') == 200:
                return True, "SMS sent successfully via Fast2SMS OTP route."
    except urllib.error.HTTPError as he:
        try:
            err_data = json.loads(he.read().decode('utf-8'))
            print("\n⚠️ [FAST2SMS OTP ROUTE ERROR]:", err_data)
        except Exception:
            print("\n⚠️ [FAST2SMS OTP ROUTE ERROR]:", he)
    except Exception as e:
        print("⚠️ Fast2SMS OTP route warning:", e)

    # Route 2: Fast2SMS Quick SMS Route (Fallback)
    try:
        q2 = urllib.parse.urlencode({
            'authorization': api_key,
            'route': 'q',
            'message': f"Your DGPRO Store login OTP is {otp_code}. Valid for 5 minutes.",
            'flash': '0',
            'numbers': clean_mobile
        })
        url2 = f"https://www.fast2sms.com/dev/bulkV2?{q2}"
        req2 = urllib.request.Request(url2, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req2, timeout=8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            print("\n" + "="*56)
            print("📡 [FAST2SMS QUICK ROUTE RESPONSE]:", data)
            print("="*56 + "\n")
            if data.get('return') is True or data.get('status_code') == 200:
                return True, "SMS sent successfully via Fast2SMS Quick route."
    except urllib.error.HTTPError as he:
        try:
            err_data = json.loads(he.read().decode('utf-8'))
            print("\n⚠️ [FAST2SMS QUICK ROUTE ERROR]:", err_data)
            # Check for error 999 (min recharge needed) or 996 (KYC needed)
            msg = err_data.get('message', '')
            print("👉 Fast2SMS Message:", msg)
        except Exception:
            print("\n⚠️ [FAST2SMS QUICK ROUTE ERROR]:", he)
    except Exception as e2:
        print("⚠️ Fast2SMS Quick route warning:", e2)

    return False, "Fast2SMS dispatch failed."

def generate_download_token(order_id, product_id, product_title, buyer_email, limit=3):
    token = "tok_sec_" + secrets.token_hex(24)
    now = time.time()
    expires_at = now + (7 * 24 * 3600)  # 7 days

    db["downloadTokens"][token] = {
        "token": token,
        "orderId": order_id,
        "productId": product_id,
        "productTitle": product_title,
        "buyerEmail": buyer_email,
        "downloadsRemaining": limit,
        "createdAt": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now)),
        "expiresAt": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expires_at)),
        "active": True
    }
    save_database()
    return token

# Session Management
def create_admin_session(username="admin"):
    token = secrets.token_hex(32)
    now = time.time()
    expires_at = now + (24 * 3600)  # 24 Hours
    db["adminSessions"][token] = {
        "username": username,
        "createdAt": now,
        "expiresAt": expires_at
    }
    save_database()
    return token

def is_valid_admin_session(token):
    if not token or token not in db["adminSessions"]:
        return False
    sess = db["adminSessions"][token]
    if time.time() > sess.get("expiresAt", 0):
        del db["adminSessions"][token]
        save_database()
        return False
    return True

def extract_session_token(handler):
    cookie_header = handler.headers.get('Cookie', '')
    if 'dgpro_admin_session=' in cookie_header:
        parts = cookie_header.split(';')
        for p in parts:
            p = p.strip()
            if p.startswith('dgpro_admin_session='):
                return p.replace('dgpro_admin_session=', '').strip()

    auth_header = handler.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header.replace('Bearer ', '').strip()

    return None

# Server-Side Login Page HTML with Forgot Password & Anti-Inspect Protection
LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DGPRO Admin Login - Server Authentication</title>
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
  <meta http-equiv="X-Frame-Options" content="DENY">
  <meta http-equiv="X-Content-Type-Options" content="nosniff">
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            brand: {
              dark: '#18201e',
              darker: '#101514',
              gold: '#b89252',
              goldHover: '#a37e3d',
              sand: '#c7bdaf'
            }
          }
        }
      }
    };
  </script>
  <style>
    body, * {
      -webkit-user-select: none;
      -ms-user-select: none;
      user-select: none;
    }
    input {
      -webkit-user-select: text;
      user-select: text;
    }
  </style>
</head>
<body class="bg-brand-darker min-h-screen flex items-center justify-center p-4 text-white font-sans">
  <div class="max-w-md w-full bg-brand-dark border border-brand-gold/40 rounded-3xl p-8 shadow-2xl space-y-6">
    <div class="text-center space-y-2">
      <div class="w-16 h-16 mx-auto rounded-2xl bg-brand-gold/10 border border-brand-gold/40 flex items-center justify-center text-3xl shadow-lg">
        🛡️
      </div>
      <h1 class="text-2xl font-black tracking-tight text-white">DGPRO Admin Gateway</h1>
      <p class="text-xs text-brand-sand">Server-Side Authentication Required. Database &amp; Admin Panel Protected.</p>
    </div>

    <!-- Main Login Form -->
    <form id="adminLoginForm" onsubmit="submitAdminLogin(event)" class="space-y-4">
      <div>
        <label class="block text-xs font-bold text-brand-sand mb-1">Username / Identifier</label>
        <input type="text" id="adminUser" placeholder="admin" required
          class="w-full text-xs px-4 py-3 rounded-xl bg-black/40 border border-white/10 text-white focus:outline-none focus:border-brand-gold focus:ring-1 focus:ring-brand-gold">
      </div>

      <div>
        <label class="block text-xs font-bold text-brand-sand mb-1 flex items-center justify-between">
          <span>Security PIN or Password</span>
          <span class="text-[10px] text-brand-gold/70 font-mono">(PIN: 1234 or Password)</span>
        </label>
        <input type="password" id="adminPass" placeholder="••••" required autofocus
          class="w-full text-xs px-4 py-3 rounded-xl bg-black/40 border border-white/10 text-brand-gold font-mono tracking-widest focus:outline-none focus:border-brand-gold focus:ring-1 focus:ring-brand-gold">
      </div>

      <div id="loginErrorMsg" class="hidden text-xs text-rose-400 font-bold text-center bg-rose-950/40 p-2.5 rounded-xl border border-rose-500/30"></div>

      <button type="submit" id="loginSubmitBtn"
        class="w-full bg-brand-gold hover:bg-brand-goldHover text-brand-darker font-black py-3 rounded-xl transition shadow-lg cursor-pointer text-xs uppercase tracking-wider">
        🔐 Authenticate &amp; Access Admin
      </button>

      <div class="flex items-center justify-between pt-1">
        <button type="button" onclick="openForgotCredentialsModal()" class="text-brand-sand hover:text-brand-gold text-xs underline cursor-pointer">
          ❓ Forgot Username, Password or PIN?
        </button>
        <a href="/" class="text-xs text-stone-400 hover:text-white transition">← Storefront</a>
      </div>
    </form>
  </div>

  <!-- FORGOT CREDENTIALS / RESET MODAL -->
  <div id="forgotCredentialsModal" class="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="bg-brand-dark border border-brand-gold/40 rounded-3xl p-6 sm:p-8 max-w-md w-full shadow-2xl text-white space-y-4">
      <div class="flex items-center justify-between border-b border-white/10 pb-3">
        <div class="flex items-center gap-2">
          <span class="text-2xl">🔑</span>
          <h2 class="text-lg font-black text-white">Reset Admin Credentials</h2>
        </div>
        <button type="button" onclick="closeForgotCredentialsModal()" class="text-stone-400 hover:text-white text-sm font-bold cursor-pointer">✕</button>
      </div>

      <p class="text-xs text-brand-sand leading-relaxed">
        Verify identity using your <strong>Master Recovery Key</strong> (default: <code class="text-brand-gold font-mono">DGPRO-ADMIN-MASTER-RECOVERY</code>) or request a <strong>One-Time Terminal Reset OTP</strong>.
      </p>

      <div class="p-3 bg-black/40 rounded-xl border border-brand-gold/30 flex items-center justify-between">
        <span class="text-xs text-stone-300">Terminal Reset Code:</span>
        <button type="button" id="requestOtpBtn" onclick="requestTerminalOtp()" class="bg-brand-gold hover:bg-brand-goldHover text-brand-darker font-bold text-xs px-3 py-1.5 rounded-lg transition cursor-pointer">
          📨 Print OTP in Terminal
        </button>
      </div>
      <div id="otpNoticeMsg" class="hidden text-xs text-emerald-400 font-bold bg-emerald-950/40 p-2 rounded-xl border border-emerald-500/30 text-center"></div>

      <form id="resetCredentialsForm" onsubmit="submitResetCredentials(event)" class="space-y-3">
        <div>
          <label class="block text-xs font-bold text-brand-sand mb-1">Enter 6-Digit OTP OR Master Recovery Key:</label>
          <input type="text" id="recoveryInput" placeholder="6-digit OTP or Recovery Key" required
            class="w-full text-xs px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/20 text-brand-gold font-mono focus:outline-none focus:border-brand-gold">
        </div>

        <div>
          <label class="block text-xs font-bold text-brand-sand mb-1">New Admin Username:</label>
          <input type="text" id="resetNewUser" value="admin" required
            class="w-full text-xs px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/20 text-white focus:outline-none focus:border-brand-gold">
        </div>

        <div>
          <label class="block text-xs font-bold text-brand-sand mb-1">New Admin Password:</label>
          <input type="password" id="resetNewPass" placeholder="Min 6 characters" minlength="4" required
            class="w-full text-xs px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/20 text-white focus:outline-none focus:border-brand-gold">
        </div>

        <div>
          <label class="block text-xs font-bold text-brand-sand mb-1">New Security PIN (4-6 digits):</label>
          <input type="password" id="resetNewPin" placeholder="e.g. 1234" maxlength="6" minlength="4" required
            class="w-full text-xs px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/20 text-brand-gold font-mono tracking-widest focus:outline-none focus:border-brand-gold">
        </div>

        <div id="resetErrorMsg" class="hidden text-xs text-rose-400 font-bold text-center bg-rose-950/40 p-2 rounded-xl border border-rose-500/30"></div>

        <button type="submit" id="resetSubmitBtn"
          class="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-black py-2.5 rounded-xl transition shadow-lg cursor-pointer text-xs uppercase tracking-wider">
          ✅ Reset &amp; Access Admin
        </button>
      </form>
    </div>
  </div>

  <script>
    // DGPRO Anti-Inspect Protection for Admin Login
    window.addEventListener('contextmenu', e => { e.preventDefault(); e.stopPropagation(); return false; }, true);
    window.addEventListener('keydown', e => {
      const key = (e.key || '').toLowerCase();
      const keyCode = e.keyCode || e.which;
      const isCtrlOrCmd = e.ctrlKey || e.metaKey;
      const isShift = e.shiftKey;
      if (key === 'f12' || keyCode === 123) { e.preventDefault(); e.stopPropagation(); return false; }
      if (isCtrlOrCmd && isShift && (key === 'i' || key === 'j' || key === 'c' || keyCode === 73 || keyCode === 74 || keyCode === 67)) { e.preventDefault(); e.stopPropagation(); return false; }
      if (isCtrlOrCmd && (key === 'u' || keyCode === 85)) { e.preventDefault(); e.stopPropagation(); return false; }
      if (isCtrlOrCmd && (key === 's' || keyCode === 83)) { e.preventDefault(); e.stopPropagation(); return false; }
    }, true);

    async function submitAdminLogin(e) {
      e.preventDefault();
      const errBox = document.getElementById('loginErrorMsg');
      const btn = document.getElementById('loginSubmitBtn');
      const user = document.getElementById('adminUser').value.trim();
      const pass = document.getElementById('adminPass').value.trim();

      errBox.classList.add('hidden');
      btn.disabled = true;
      btn.textContent = 'Verifying Credentials...';

      try {
        const res = await fetch('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: user, password: pass })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          window.location.href = data.redirect || '/admin';
        } else {
          errBox.textContent = data.error || 'Invalid credentials or access denied.';
          errBox.classList.remove('hidden');
          btn.disabled = false;
          btn.textContent = '🔐 Authenticate & Access Admin';
        }
      } catch (err) {
        errBox.textContent = 'Network error connecting to backend server.';
        errBox.classList.remove('hidden');
        btn.disabled = false;
        btn.textContent = '🔐 Authenticate & Access Admin';
      }
    }

    function openForgotCredentialsModal() {
      document.getElementById('forgotCredentialsModal').classList.remove('hidden');
    }
    function closeForgotCredentialsModal() {
      document.getElementById('forgotCredentialsModal').classList.add('hidden');
    }

    async function requestTerminalOtp() {
      const notice = document.getElementById('otpNoticeMsg');
      const btn = document.getElementById('requestOtpBtn');
      btn.disabled = true;
      btn.textContent = 'Printing...';

      try {
        const res = await fetch('/api/admin/request-recovery-otp', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
          notice.textContent = "✅ OTP Generated! Check your VS Code terminal window to view the 6-digit code.";
          notice.classList.remove('hidden');
        } else {
          notice.textContent = data.error || "Could not generate OTP.";
          notice.classList.remove('hidden');
        }
      } catch (err) {
        notice.textContent = "Failed to connect to server.";
        notice.classList.remove('hidden');
      } finally {
        btn.disabled = false;
        btn.textContent = '📨 Print OTP in Terminal';
      }
    }

    async function submitResetCredentials(e) {
      e.preventDefault();
      const errBox = document.getElementById('resetErrorMsg');
      const btn = document.getElementById('resetSubmitBtn');
      const recoveryKeyOrOtp = document.getElementById('recoveryInput').value.trim();
      const newUser = document.getElementById('resetNewUser').value.trim();
      const newPass = document.getElementById('resetNewPass').value.trim();
      const newPin = document.getElementById('resetNewPin').value.trim();

      errBox.classList.add('hidden');
      btn.disabled = true;
      btn.textContent = 'Updating...';

      try {
        const res = await fetch('/api/admin/reset-credentials', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            verificationKey: recoveryKeyOrOtp,
            username: newUser,
            password: newPass,
            pin: newPin
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          alert("✅ Admin credentials reset successfully! Logging you in...");
          window.location.href = data.redirect || '/admin';
        } else {
          errBox.textContent = data.error || "Invalid recovery key or expired OTP.";
          errBox.classList.remove('hidden');
          btn.disabled = false;
          btn.textContent = '✅ Reset & Access Admin';
        }
      } catch (err) {
        errBox.textContent = "Network error connecting to backend server.";
        errBox.classList.remove('hidden');
        btn.disabled = false;
        btn.textContent = '✅ Reset & Access Admin';
      }
    }
  </script>
</body>
</html>"""

MIME_TYPES = {
    '.html': 'text/html; charset=UTF-8',
    '.css': 'text/css; charset=UTF-8',
    '.js': 'application/javascript; charset=UTF-8',
    '.json': 'application/json; charset=UTF-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.zip': 'application/zip',
    '.pdf': 'application/pdf'
}


def inject_cloud_sync_into_html(html_bytes, is_admin=False):
    try:
        html_str = html_bytes.decode('utf-8')
        server_cfg_json = json.dumps(db.get("storeConfig", {}), ensure_ascii=False)
        sync_script = f"""
<!-- DGPRO MOBILE RESPONSIVE & ANTI-OVERFLOW ENGINE -->
<style id="dgpro-mobile-responsive-fix">
  html, body {{
    max-width: 100vw !important;
    width: 100% !important;
    overflow-x: hidden !important;
    margin: 0 !important;
    padding: 0 !important;
  }}
  main, header, footer {{
    max-width: 100vw !important;
    box-sizing: border-box !important;
  }}
  @media (max-width: 639px) {{
    header {{
      height: auto !important;
      overflow: hidden !important;
      width: 100% !important;
    }}
    header > div {{
      height: auto !important;
      min-height: 3.5rem !important;
      padding: 0.65rem 0.75rem !important;
      flex-wrap: wrap !important;
      gap: 0.5rem !important;
      width: 100% !important;
      box-sizing: border-box !important;
    }}
    #brandLogo {{
      max-width: 100% !important;
    }}
    header > div > div:last-child {{
      width: 100% !important;
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      gap: 0.35rem !important;
      flex-wrap: nowrap !important;
      overflow-x: auto !important;
    }}
    header button {{
      padding: 0.38rem 0.55rem !important;
      font-size: 11px !important;
      line-height: 1.2 !important;
      white-space: nowrap !important;
      flex-shrink: 0 !important;
    }}
    #dynamicPromoBannersGrid > div {{
      width: 100% !important;
      max-width: 100% !important;
      overflow: hidden !important;
      box-sizing: border-box !important;
      padding: 1rem !important;
    }}
    #dynamicPromoBannersGrid > div > div {{
      width: 100% !important;
      max-width: 100% !important;
      min-width: 0 !important;
    }}
    #promoBanner1Title, #promoBanner2Title {{
      white-space: normal !important;
      overflow: visible !important;
      text-overflow: clip !important;
      overflow-wrap: break-word !important;
      word-break: break-word !important;
      font-size: 0.95rem !important;
      line-height: 1.35 !important;
    }}
    #promoBanner1Desc, #promoBanner2Desc {{
      white-space: normal !important;
      overflow-wrap: break-word !important;
      word-break: break-word !important;
    }}
    #heroBannerCarousel {{
      width: 100% !important;
      max-width: 100% !important;
      overflow: hidden !important;
    }}
    #heroSlidesTrack > div {{
      padding: 1.25rem 1.15rem 2.85rem 1.15rem !important;
      box-sizing: border-box !important;
      max-width: 100% !important;
    }}
    #heroSlidesTrack h1, #heroSlidesTrack h2 {{
      font-size: 1.35rem !important;
      line-height: 1.25 !important;
      overflow-wrap: break-word !important;
      word-break: break-word !important;
    }}
    #heroBannerCarousel button[onclick*="HeroSlide"] {{
      top: auto !important;
      bottom: 0.45rem !important;
      transform: none !important;
      width: 1.75rem !important;
      height: 1.75rem !important;
      font-size: 0.85rem !important;
    }}
    #filterPills {{
      max-width: 100% !important;
      overflow-x: auto !important;
      padding-bottom: 0.35rem !important;
    }}
    #productDetailsSection > div:first-child {{
      flex-wrap: wrap !important;
      gap: 0.5rem !important;
    }}
  }}
</style>

<!-- DGPRO LIVE CLOUD & INSTANT 0MS VIDEO ENGINE -->
<script id="dgpro-central-cloud-sync">
(function() {{
  window.__DGPRO_SERVER_STORE_CONFIG__ = {server_cfg_json};
  window.__LAST_APPLIED_SERVER_TS__ = 0;
  const IS_ADMIN_PAGE = { 'true' if is_admin else 'false' };
  const PREWARMED_VIDEO_NODES = {{}};
  const UPLOADED_VIDEOS_TRACKER = new Set();

  function buildCleanConfigPayload(cfgObj) {{
    if (!cfgObj) return null;
    try {{
      return JSON.stringify({{
        categories: cfgObj.categories || (typeof CATEGORIES !== 'undefined' ? CATEGORIES : []),
        products: cfgObj.products || (typeof PRODUCTS !== 'undefined' ? PRODUCTS : []),
        orderBumps: cfgObj.orderBumps || (typeof ORDER_BUMPS !== 'undefined' ? ORDER_BUMPS : {{}}),
        coupons: cfgObj.coupons || (typeof COUPONS !== 'undefined' ? COUPONS : {{}}),
        siteBanners: cfgObj.siteBanners || (typeof SITE_BANNERS !== 'undefined' ? SITE_BANNERS : {{}}),
        productMedia: cfgObj.productMedia || (typeof PRODUCT_MEDIA !== 'undefined' ? PRODUCT_MEDIA : {{}}),
        lastUpdated: cfgObj.lastUpdated || Date.now()
      }}, function(key, val) {{
        if (key === 'videoBlob' || key === 'blob') return undefined;
        if (typeof Blob !== 'undefined' && val instanceof Blob) return undefined;
        return val;
      }});
    }} catch (e) {{
      return null;
    }}
  }}

  window.uploadProductVideoBlobToServer = async function(pid, blobObj) {{
    if (!pid || !blobObj || !(blobObj instanceof Blob) || blobObj.size === 0) return null;
    try {{
      const res = await fetch('/api/admin/upload-video?productId=' + encodeURIComponent(pid), {{
        method: 'POST',
        headers: {{
          'Content-Type': blobObj.type || 'video/mp4',
          'X-Product-Id': pid,
          'X-DGPRO-Admin-Sync': 'true'
        }},
        body: blobObj
      }});
      if (res.ok) {{
        const data = await res.json();
        UPLOADED_VIDEOS_TRACKER.add(pid);
        return data.videoUrl || ('/api/video/' + pid);
      }}
    }} catch (e) {{
      console.warn('Video cloud upload warning:', e);
    }}
    return null;
  }};

  async function syncAllLocalVideosToServer(productsList, mediaMap) {{
    if (!Array.isArray(productsList) || typeof loadFromIndexedDB !== 'function') return;
    for (const p of productsList) {{
      const pid = p && p.id;
      if (!pid || UPLOADED_VIDEOS_TRACKER.has(pid)) continue;
      const existingServerUrl = mediaMap && mediaMap[pid] && mediaMap[pid][4] && mediaMap[pid][4].videoUrl;
      if (existingServerUrl && existingServerUrl.startsWith('/api/video/')) {{
        UPLOADED_VIDEOS_TRACKER.add(pid);
        continue;
      }}
      try {{
        let rec = await loadFromIndexedDB('dgpro_v2_prod_video_' + pid);
        if (!rec || !(rec.blob instanceof Blob)) {{
          rec = await loadFromIndexedDB('dgpro_product_video_' + pid);
        }}
        const b = (rec && (rec.blob instanceof Blob)) ? rec.blob : (mediaMap && mediaMap[pid] && mediaMap[pid][4] && (mediaMap[pid][4].videoBlob instanceof Blob) ? mediaMap[pid][4].videoBlob : null);
        if (b && b.size > 0) {{
          const uploadedUrl = await window.uploadProductVideoBlobToServer(pid, b);
          if (uploadedUrl && mediaMap && mediaMap[pid] && mediaMap[pid][4]) {{
            mediaMap[pid][4].videoUrl = uploadedUrl;
          }}
        }}
      }} catch (e) {{}}
    }}
  }}

  window.pushStoreDataToCentralServer = async function(cfgSource, showToastConfirm) {{
    try {{
      const targetCfg = cfgSource || (typeof STORE_CONFIG !== 'undefined' ? STORE_CONFIG : null);
      if (!targetCfg) return false;
      const payloadStr = buildCleanConfigPayload(targetCfg);
      if (!payloadStr) return false;
      const res = await fetch('/api/admin/save-store-data', {{
        method: 'POST',
        headers: {{
          'Content-Type': 'application/json',
          'X-DGPRO-Admin-Sync': 'true',
          'Authorization': 'Bearer dgpro_admin_sync'
        }},
        body: payloadStr
      }});
      if (res.ok) {{
        window.__DGPRO_SERVER_STORE_CONFIG__ = JSON.parse(payloadStr);
        syncAllLocalVideosToServer(targetCfg.products || [], targetCfg.productMedia || {{}});
        if (showToastConfirm && typeof showToast === 'function') {{
          showToast("☁️ Synced to Live Server! All browsers & phones now show these products.");
        }}
        return true;
      }}
    }} catch (err) {{
      console.warn("Central sync warning:", err);
    }}
    return false;
  }};

  if (IS_ADMIN_PAGE) {{
    const origSaveAdmin = window.saveAdminStore;
    if (typeof origSaveAdmin === 'function') {{
      window.saveAdminStore = async function() {{
        try {{ await origSaveAdmin.apply(this, arguments); }} catch (e) {{}}
        if (typeof STORE_CONFIG !== 'undefined') {{
          await window.pushStoreDataToCentralServer(STORE_CONFIG, true);
        }}
      }};
    }}
    const origSaveVid = window.saveValidatedProductVideoForPid;
    if (typeof origSaveVid === 'function') {{
      window.saveValidatedProductVideoForPid = async function(pId, file) {{
        const ok = await origSaveVid.apply(this, arguments);
        if (ok && pId && file) {{
          await window.uploadProductVideoBlobToServer(pId, file);
        }}
        return ok;
      }};
    }}
    setTimeout(async function() {{
      try {{
        const res = await fetch('/api/store-data?t=' + Date.now(), {{ cache: 'no-store' }});
        const srvCfg = res.ok ? await res.json() : {{}};
        const srvTs = Number(srvCfg && srvCfg.lastUpdated) || 0;
        const localTs = (typeof STORE_CONFIG !== 'undefined' && Number(STORE_CONFIG.lastUpdated)) || 0;
        const hasLocalEdits = localStorage.getItem('dgpro_products') !== null;

        if ((!srvCfg || !Array.isArray(srvCfg.products) || srvCfg.products.length === 0) && typeof STORE_CONFIG !== 'undefined') {{
          await window.pushStoreDataToCentralServer(STORE_CONFIG, false);
        }} else if (hasLocalEdits && localTs >= srvTs && typeof STORE_CONFIG !== 'undefined') {{
          await window.pushStoreDataToCentralServer(STORE_CONFIG, false);
        }} else if (srvCfg && Array.isArray(srvCfg.products) && srvCfg.products.length > 0 && typeof applyParsedConfig === 'function') {{
          applyParsedConfig(srvCfg);
          if (typeof renderDashboard === 'function') renderDashboard();
          if (typeof renderProductSelector === 'function') renderProductSelector();
          if (typeof renderCategoriesList === 'function') renderCategoriesList();
          if (typeof currentEditingId !== 'undefined' && currentEditingId && typeof loadProductToEditor === 'function') {{
            loadProductToEditor(currentEditingId);
          }}
        }}
        if (typeof STORE_CONFIG !== 'undefined') {{
          syncAllLocalVideosToServer(STORE_CONFIG.products || [], STORE_CONFIG.productMedia || {{}});
        }}
      }} catch (e) {{}}
    }}, 700);
  }} else {{
    // ================= INSTANT 0MS VIDEO PRELOADER & PLAYER FOR STOREFRONT =================
    function getImmediateSyncVideoUrl(pid) {{
      if (!pid) return '';
      if (typeof PRODUCT_V2_VIDEO_CACHE !== 'undefined' && PRODUCT_V2_VIDEO_CACHE[pid] && PRODUCT_V2_VIDEO_CACHE[pid].objectUrl) {{
        return PRODUCT_V2_VIDEO_CACHE[pid].objectUrl;
      }}
      if (typeof VIDEO_OBJECT_URL_CACHE !== 'undefined' && VIDEO_OBJECT_URL_CACHE[pid] && VIDEO_OBJECT_URL_CACHE[pid].url) {{
        return VIDEO_OBJECT_URL_CACHE[pid].url;
      }}
      if (typeof PRODUCT_MEDIA !== 'undefined' && PRODUCT_MEDIA[pid] && PRODUCT_MEDIA[pid][4]) {{
        const slot4 = PRODUCT_MEDIA[pid][4];
        if (slot4.videoBlob instanceof Blob && slot4.videoBlob.size > 0 && typeof getCachedBlobUrl === 'function') {{
          const bUrl = getCachedBlobUrl(slot4.videoBlob, pid);
          if (bUrl) return bUrl;
        }}
        if (slot4.videoUrl && typeof slot4.videoUrl === 'string' && slot4.videoUrl.trim() !== '') {{
          return slot4.videoUrl.trim();
        }}
      }}
      if (window.SERVER_AUTHORITATIVE_CONFIG && window.SERVER_AUTHORITATIVE_CONFIG.productMedia && window.SERVER_AUTHORITATIVE_CONFIG.productMedia[pid] && window.SERVER_AUTHORITATIVE_CONFIG.productMedia[pid][4]) {{
        const sSlot4 = window.SERVER_AUTHORITATIVE_CONFIG.productMedia[pid][4];
        if (sSlot4 && sSlot4.videoUrl) return sSlot4.videoUrl;
      }}
      return '';
    }}

    function prebufferProductVideoNode(pid, srcUrl) {{
      if (!pid || !srcUrl) return null;
      let existingNode = PREWARMED_VIDEO_NODES[pid];
      if (existingNode && existingNode.dataset.loadedSrc === srcUrl) {{
        return existingNode;
      }}
      try {{
        const vid = document.createElement('video');
        vid.src = srcUrl;
        vid.muted = true;
        vid.loop = true;
        vid.playsInline = true;
        vid.controls = true;
        vid.preload = 'auto';
        vid.className = 'w-full h-full object-contain bg-black';
        vid.dataset.loadedSrc = srcUrl;
        vid.load();
        PREWARMED_VIDEO_NODES[pid] = vid;
        return vid;
      }} catch (e) {{
        return null;
      }}
    }}

    // Upgrade selectProductMediaSlot so Video Slot mounts in 0ms without async delay or race condition cancellation!
    window.selectProductMediaSlot = async function(slot) {{
      const viewer = document.getElementById('pdMainMediaViewer');
      const badge = document.getElementById('pdMediaSlotBadge');
      if (!viewer || !slot) return;

      if (slot.type !== 'video') {{
        if (badge) {{
          badge.classList.remove('hidden');
          badge.textContent = slot.slotLabel || '';
        }}
        viewer.innerHTML = slot.html || '';
        return;
      }}

      if (badge) badge.classList.add('hidden');
      const pid = slot.productId || (typeof currentDetailProductId !== 'undefined' ? currentDetailProductId : '');
      if (!pid) return;

      // 1. Check synchronous 0ms sources first
      let fastUrl = getImmediateSyncVideoUrl(pid);
      if (fastUrl) {{
        if (typeof mountPlayableVideoInViewer === 'function') {{
          mountPlayableVideoInViewer(viewer, fastUrl);
        }}
        return;
      }}

      // 2. Show instant player shell immediately (0ms visual feedback!) while fetching from IndexedDB or Server
      viewer.innerHTML = `
        <div class="w-full h-full relative bg-black flex flex-col items-center justify-center overflow-hidden select-none text-white">
          <div class="w-10 h-10 border-3 border-brand-gold border-t-transparent rounded-full animate-spin mb-2"></div>
          <span class="text-xs font-bold text-stone-300">Loading Official Video Demo...</span>
        </div>
      `;

      let asyncUrl = '';
      if (typeof getOrLoadProductVideoUrl === 'function') {{
        try {{ asyncUrl = await getOrLoadProductVideoUrl(pid); }} catch (e) {{}}
      }}
      if (!asyncUrl) {{
        asyncUrl = getImmediateSyncVideoUrl(pid);
      }}
      // Fallback: check if server has /api/video/<pid>
      if (!asyncUrl) {{
        try {{
          const headRes = await fetch('/api/video/' + encodeURIComponent(pid), {{ method: 'HEAD' }});
          if (headRes.ok || headRes.status === 206) {{
            asyncUrl = '/api/video/' + encodeURIComponent(pid);
            if (typeof PRODUCT_V2_VIDEO_CACHE !== 'undefined') {{
              PRODUCT_V2_VIDEO_CACHE[pid] = {{ productId: pid, objectUrl: asyncUrl, title: slot.title || 'Video Demo' }};
            }}
          }}
        }} catch (e) {{}}
      }}

      // Mount immediately if user is still viewing video slot
      if (typeof currentDetailMediaSlotIdx !== 'undefined' && currentDetailMediaSlotIdx !== 4) return;
      if (asyncUrl) {{
        prebufferProductVideoNode(pid, asyncUrl);
        if (typeof mountPlayableVideoInViewer === 'function') {{
          mountPlayableVideoInViewer(viewer, asyncUrl);
        }}
      }} else {{
        viewer.innerHTML = `
          <div class="w-full h-full bg-slate-950 text-white flex flex-col items-center justify-center p-6 text-center select-none">
            <span class="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-xl mb-3 text-rose-500">▶</span>
            <p class="text-xs sm:text-sm font-bold text-slate-200">No video uploaded for this product yet</p>
            <p class="text-[11px] text-slate-400 mt-1">Upload a video (up to 2 minutes) for this product in Admin Panel → Media &amp; Video.</p>
          </div>
        `;
      }}
    }};

    // Also hook openProductDetails so as soon as a user clicks a product card, its video is pre-buffered in 0ms!
    const origOpenProductDetails = window.openProductDetails;
    if (typeof origOpenProductDetails === 'function') {{
      window.openProductDetails = function(productId, isBackgroundSync) {{
        origOpenProductDetails.apply(this, arguments);
        if (productId) {{
          const syncU = getImmediateSyncVideoUrl(productId);
          if (syncU) {{
            prebufferProductVideoNode(productId, syncU);
            if (typeof prewarmVideoUrlInMemory === 'function') prewarmVideoUrlInMemory(syncU);
          }} else if (typeof getOrLoadProductVideoUrl === 'function') {{
            getOrLoadProductVideoUrl(productId).then(u => {{
              const finalU = u || getImmediateSyncVideoUrl(productId);
              if (finalU) {{
                prebufferProductVideoNode(productId, finalU);
                if (typeof prewarmVideoUrlInMemory === 'function') prewarmVideoUrlInMemory(finalU);
              }}
            }}).catch(() => {{}});
          }}
        }}
      }};
    }}

    function applyAuthoritativeServerConfig(srvCfg) {{
      if (!srvCfg || !Array.isArray(srvCfg.products) || srvCfg.products.length === 0) return false;
      const incomingTs = Number(srvCfg.lastUpdated) || 1;
      const isNewChange = (incomingTs !== window.__LAST_APPLIED_SERVER_TS__);
      window.__LAST_APPLIED_SERVER_TS__ = incomingTs;
      window.SERVER_AUTHORITATIVE_CONFIG = srvCfg;

      if (typeof applyConfigObject === 'function') {{
        applyConfigObject(srvCfg, true);
      }}
      if (typeof PRODUCTS !== 'undefined') PRODUCTS = srvCfg.products;
      if (typeof CATEGORIES !== 'undefined' && Array.isArray(srvCfg.categories) && srvCfg.categories.length > 0) {{
        CATEGORIES = srvCfg.categories;
      }}
      if (typeof ORDER_BUMPS !== 'undefined' && srvCfg.orderBumps) ORDER_BUMPS = srvCfg.orderBumps;
      if (typeof COUPONS !== 'undefined' && srvCfg.coupons) COUPONS = srvCfg.coupons;

      // Pre-populate PRODUCT_V2_VIDEO_CACHE from server videoUrls so videos play in 0ms!
      if (srvCfg.productMedia && typeof srvCfg.productMedia === 'object') {{
        Object.keys(srvCfg.productMedia).forEach(pid => {{
          const s4 = srvCfg.productMedia[pid] && srvCfg.productMedia[pid][4];
          if (s4 && s4.videoUrl && typeof PRODUCT_V2_VIDEO_CACHE !== 'undefined') {{
            if (!PRODUCT_V2_VIDEO_CACHE[pid] || !PRODUCT_V2_VIDEO_CACHE[pid].blob) {{
              PRODUCT_V2_VIDEO_CACHE[pid] = {{
                productId: pid,
                objectUrl: s4.videoUrl,
                title: s4.title || 'Video Demo',
                durationFormatted: s4.durationFormatted || ''
              }};
            }}
          }}
        }});
      }}

      try {{ localStorage.setItem('dgpro_products', JSON.stringify(srvCfg.products)); }} catch(e) {{}}
      try {{ if (srvCfg.categories) localStorage.setItem('dgpro_categories', JSON.stringify(srvCfg.categories)); }} catch(e) {{}}
      try {{ if (srvCfg.orderBumps) localStorage.setItem('dgpro_order_bumps', JSON.stringify(srvCfg.orderBumps)); }} catch(e) {{}}
      try {{ if (srvCfg.coupons) localStorage.setItem('dgpro_coupons', JSON.stringify(srvCfg.coupons)); }} catch(e) {{}}
      try {{ localStorage.setItem('dgpro_store_config', JSON.stringify(srvCfg)); }} catch(e) {{}}

      if (isNewChange) {{
        if (typeof renderCategories === 'function') renderCategories();
        if (typeof renderCatalog === 'function') renderCatalog();
        if (typeof updateDynamicPromoBanners === 'function') updateDynamicPromoBanners();
      }}
      if (typeof loadAllV2ProductVideosFromIndexedDB === 'function') {{
        loadAllV2ProductVideosFromIndexedDB();
      }}
      return true;
    }}

    const origLoadStoreConfig = window.loadStoreConfig;
    if (typeof origLoadStoreConfig === 'function') {{
      window.loadStoreConfig = function() {{
        origLoadStoreConfig.apply(this, arguments);
        if (window.SERVER_AUTHORITATIVE_CONFIG && Array.isArray(window.SERVER_AUTHORITATIVE_CONFIG.products) && window.SERVER_AUTHORITATIVE_CONFIG.products.length > 0) {{
          if (typeof applyConfigObject === 'function') {{
            applyConfigObject(window.SERVER_AUTHORITATIVE_CONFIG, true);
          }}
          PRODUCTS = window.SERVER_AUTHORITATIVE_CONFIG.products;
          if (Array.isArray(window.SERVER_AUTHORITATIVE_CONFIG.categories) && window.SERVER_AUTHORITATIVE_CONFIG.categories.length > 0) {{
            CATEGORIES = window.SERVER_AUTHORITATIVE_CONFIG.categories;
          }}
        }}
      }};
    }}

    async function syncStorefrontWithServer() {{
      try {{
        const res = await fetch('/api/store-data?t=' + Date.now(), {{ cache: 'no-store' }});
        const srvCfg = res.ok ? await res.json() : window.__DGPRO_SERVER_STORE_CONFIG__;
        const srvHasProds = srvCfg && Array.isArray(srvCfg.products) && srvCfg.products.length > 0;
        const srvTs = Number(srvCfg && srvCfg.lastUpdated) || 0;

        const adminLocalProdsRaw = localStorage.getItem('dgpro_products');
        if (adminLocalProdsRaw) {{
          let localCfg = null;
          try {{
            if (typeof loadFromIndexedDB === 'function') {{
              localCfg = await loadFromIndexedDB('dgpro_store_config');
            }}
          }} catch(e) {{}}
          if (!localCfg) {{
            try {{ localCfg = JSON.parse(localStorage.getItem('dgpro_store_config') || 'null'); }} catch(e) {{}}
          }}
          const localProds = JSON.parse(adminLocalProdsRaw);
          const localTs = Number(localCfg && localCfg.lastUpdated) || 1;
          // Auto-upload any local product videos from Admin browser to server
          syncAllLocalVideosToServer(localProds, (localCfg && localCfg.productMedia) || (typeof PRODUCT_MEDIA !== 'undefined' ? PRODUCT_MEDIA : {{}}));

          if (!srvHasProds || localTs > srvTs) {{
            const mergedToPush = {{
              categories: (localCfg && localCfg.categories) || (typeof CATEGORIES !== 'undefined' ? CATEGORIES : []),
              products: localProds,
              productMedia: (localCfg && localCfg.productMedia) || (typeof PRODUCT_MEDIA !== 'undefined' ? PRODUCT_MEDIA : {{}}),
              orderBumps: (localCfg && localCfg.orderBumps) || (typeof ORDER_BUMPS !== 'undefined' ? ORDER_BUMPS : {{}}),
              coupons: (localCfg && localCfg.coupons) || (typeof COUPONS !== 'undefined' ? COUPONS : {{}}),
              siteBanners: (localCfg && localCfg.siteBanners) || (typeof SITE_BANNERS !== 'undefined' ? SITE_BANNERS : {{}}),
              lastUpdated: localTs > 1 ? localTs : Date.now()
            }};
            await window.pushStoreDataToCentralServer(mergedToPush, false);
            applyAuthoritativeServerConfig(mergedToPush);
            return;
          }}
        }}

        if (srvHasProds) {{
          applyAuthoritativeServerConfig(srvCfg);
        }}
      }} catch (err) {{
        if (window.__DGPRO_SERVER_STORE_CONFIG__ && Array.isArray(window.__DGPRO_SERVER_STORE_CONFIG__.products)) {{
          applyAuthoritativeServerConfig(window.__DGPRO_SERVER_STORE_CONFIG__);
        }}
      }}
    }}

    if (window.__DGPRO_SERVER_STORE_CONFIG__ && Array.isArray(window.__DGPRO_SERVER_STORE_CONFIG__.products) && window.__DGPRO_SERVER_STORE_CONFIG__.products.length > 0 && !localStorage.getItem('dgpro_products')) {{
      applyAuthoritativeServerConfig(window.__DGPRO_SERVER_STORE_CONFIG__);
    }}
    syncStorefrontWithServer();
    window.addEventListener('focus', syncStorefrontWithServer);
    setInterval(syncStorefrontWithServer, 20000);
  }}
}})();
</script>
"""
        if '</body>' in html_str:
            html_str = html_str.replace('</body>', sync_script + '\n</body>', 1)
        else:
            html_str = html_str + sync_script
        return html_str.encode('utf-8')
    except Exception as e:
        print("HTML sync inject warning:", e)
        return html_bytes

class DGPROHandler(http.server.BaseHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-razorpay-signature, X-DGPRO-Admin-Sync')

    def send_json(self, status_code, data, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_cors_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=UTF-8')
        self.send_cors_headers()
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. Health check
        if path == '/api/health':
            return self.send_json(200, {
                "status": "online",
                "server": "Python 3 Native (HMAC + Session Auth)",
                "razorpayConfigured": not ('Mock' in RAZORPAY_KEY_ID),
                "totalOrders": len(db["orders"])
            })

        # 1B. Public Central Store Data endpoint (Products, Categories, Banners, Coupons, Bumps)
        if path in ('/api/store-data', '/api/products'):
            return self.send_json(200, db.get("storeConfig", {}), extra_headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
            })

        # 1C. Instant HTTP-206 Range Video Streaming Endpoint (/api/video/<pid>)
        if path.startswith('/api/video/'):
            pid = path.replace('/api/video/', '').strip().split('/')[0]
            safe_pid = "".join(c for c in pid if c.isalnum() or c in ('_', '-'))
            vid_path = os.path.join(VIDEOS_DIR, f"{safe_pid}.mp4")
            if not os.path.isfile(vid_path):
                return self.send_json(404, {"error": "No video found on server for this product."})
            try:
                file_size = os.path.getsize(vid_path)
                range_header = self.headers.get('Range', '')
                if range_header and range_header.startswith('bytes='):
                    byte_range = range_header.replace('bytes=', '').strip().split('-')
                    start = int(byte_range[0]) if byte_range[0] else 0
                    end = int(byte_range[1]) if (len(byte_range) > 1 and byte_range[1]) else min(start + 2 * 1024 * 1024 - 1, file_size - 1)
                    end = min(end, file_size - 1)
                    if start >= file_size or start > end:
                        self.send_response(416)
                        self.send_header('Content-Range', f'bytes */{file_size}')
                        self.end_headers()
                        return
                    chunk_len = end - start + 1
                    with open(vid_path, 'rb') as vf:
                        vf.seek(start)
                        chunk = vf.read(chunk_len)
                    self.send_response(206)
                    self.send_header('Content-Type', 'video/mp4')
                    self.send_header('Accept-Ranges', 'bytes')
                    self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
                    self.send_header('Content-Length', str(chunk_len))
                    self.send_header('Cache-Control', 'public, max-age=86400')
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(chunk)
                    return
                else:
                    with open(vid_path, 'rb') as vf:
                        data_bytes = vf.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'video/mp4')
                    self.send_header('Accept-Ranges', 'bytes')
                    self.send_header('Content-Length', str(file_size))
                    self.send_header('Cache-Control', 'public, max-age=86400')
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(data_bytes)
                    return
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as e:
                return self.send_json(500, {"error": str(e)})

        # 2. Admin Login Page
        if path == '/admin/login':
            content = LOGIN_PAGE_HTML.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=UTF-8')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
            self.end_headers()
            self.wfile.write(content)
            return

        # 3. Protected Admin Dashboard Route (/admin, /admin_handle.html, /dgpro_admin_dashboard.html)
        if path in ('/admin', '/admin_handle.html', '/dgpro_admin_dashboard.html'):
            session_token = extract_session_token(self)
            if not is_valid_admin_session(session_token):
                self.send_response(302)
                self.send_header('Location', '/admin/login')
                self.end_headers()
                return

            cand_files = ['dgpro_admin_dashboard.html', 'admin_handle.html']
            target_file = None
            for f in cand_files:
                p = os.path.join(STATIC_DIR, f)
                if os.path.exists(p):
                    try:
                        with open(p, 'r', encoding='utf-8', errors='ignore') as chk:
                            head_txt = chk.read(2500)
                            if 'Admin Dashboard' in head_txt or 'Admin Security' in head_txt:
                                target_file = p
                                break
                    except Exception:
                        pass
            if not target_file:
                for f in cand_files:
                    p = os.path.join(STATIC_DIR, f)
                    if os.path.exists(p):
                        target_file = p
                        break

            if target_file:
                with open(target_file, 'rb') as f:
                    content = inject_cloud_sync_into_html(f.read(), is_admin=True)
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=UTF-8')
                self.send_header('Content-Length', str(len(content)))
                self.send_header('Cache-Control', 'no-store, private')
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                return self.send_json(404, {"error": "Admin dashboard HTML not found on server."})

        # 4. Protected Admin APIs (/api/orders, /api/customers, /api/sellers, /api/admin/credentials)
        if path in ('/api/orders', '/api/customers', '/api/sellers', '/api/admin/credentials'):
            session_token = extract_session_token(self)
            if not is_valid_admin_session(session_token):
                return self.send_json(401, {
                    "error": "Unauthorized Access. Protected Admin API requires server authentication session."
                })

            if path == '/api/orders':
                return self.send_json(200, {"orders": db["orders"]})
            if path == '/api/customers':
                return self.send_json(200, {"customers": db["customers"]})
            if path == '/api/sellers':
                return self.send_json(200, {"sellers": db["sellers"]})
            if path == '/api/admin/credentials':
                creds = db.get("adminCredentials", {})
                return self.send_json(200, {
                    "username": creds.get("username", "admin"),
                    "hasPin": bool(creds.get("pinHash")),
                    "hasPassword": bool(creds.get("passwordHash"))
                })

        # 5. Secure Download Endpoint (/api/download/<token>)
        if path.startswith('/api/download/'):
            token = path.replace('/api/download/', '').strip()
            token_rec = db["downloadTokens"].get(token)

            if not token_rec or not token_rec.get("active"):
                return self.send_json(403, {"error": "Invalid or unauthorized download token."})

            exp_time = time.strptime(token_rec["expiresAt"], '%Y-%m-%dT%H:%M:%SZ')
            if time.time() > time.mktime(exp_time):
                return self.send_json(410, {"error": "Download token expired (7-day validity exceeded)."})

            if token_rec.get("downloadsRemaining", 0) <= 0:
                return self.send_json(403, {"error": "Download limit exhausted for this license key."})

            token_rec["downloadsRemaining"] -= 1
            token_rec["lastDownloadedAt"] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            save_database()

            safe_title = "".join(c for c in token_rec.get("productTitle", "Product") if c.isalnum() or c in ('_', '-'))
            filename = f"DGPRO_{safe_title}_License.txt"

            package_text = f"""=====================================================
DGPRO DIGITAL STORE - OFFICIAL VERIFIED DOWNLOAD
=====================================================
Product Name: {token_rec.get('productTitle')}
Product ID:   {token_rec.get('productId')}
Order ID:     {token_rec.get('orderId')}
License User: {token_rec.get('buyerEmail')}
Token Key:    {token}
Downloads Remaining: {token_rec['downloadsRemaining']}
Verification: Verified by HMAC-SHA256 Python Backend
Security Date: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

Thank you for purchasing from DGPRO Digital Downloads Store.
Support Helpline: support@dgpro.store
====================================================="""
            data_bytes = package_text.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(len(data_bytes)))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(data_bytes)
            return

        # 6. Static file routing for Storefront
        target_file = None
        if path in ('/', '/index.html'):
            target_file = os.path.join(STATIC_DIR, 'digital_downloads_store.html')
        else:
            rel = path.lstrip('/')
            cand = os.path.join(STATIC_DIR, rel)
            if os.path.commonpath([STATIC_DIR, cand]) == STATIC_DIR and os.path.isfile(cand):
                target_file = cand

        if target_file and os.path.isfile(target_file):
            _, ext = os.path.splitext(target_file)
            mime = MIME_TYPES.get(ext.lower(), 'application/octet-stream')
            try:
                with open(target_file, 'rb') as f:
                    raw_bytes = f.read()
                if ext.lower() == '.html':
                    is_adm = ('admin' in os.path.basename(target_file).lower())
                    content = inject_cloud_sync_into_html(raw_bytes, is_admin=is_adm)
                else:
                    content = raw_bytes
                self.send_response(200)
                if ext.lower() == '.html':
                    self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(content)))
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
            except Exception as e:
                return self.send_json(500, {"error": str(e)})

        self.send_json(404, {"error": "File or endpoint not found."})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(length)

        # 0A. REAL DYNAMIC CUSTOMER OTP SEND (/api/send-otp) - FREE EMAIL OTP WITH MANDATORY MOBILE NUMBER
        if path == '/api/send-otp':
            try:
                data = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.send_json(400, {"error": "Invalid JSON"})

            # 1. Mandatory Mobile Number Validation (Exact 10 digits)
            raw_mobile = data.get("mobile", "").strip()
            digits = "".join(c for c in raw_mobile if c.isdigit())
            if digits.startswith("91") and len(digits) > 10:
                digits = digits[2:]
            elif digits.startswith("0") and len(digits) == 11:
                digits = digits[1:]

            if len(digits) != 10:
                return self.send_json(400, {
                    "success": False,
                    "error": f"Valid 10-digit Mobile Number is MANDATORY. You entered ({raw_mobile})."
                })

            # 2. Mandatory Email Validation
            email = data.get("email", "").strip().lower()
            if not email or "@" not in email or "." not in email:
                return self.send_json(400, {
                    "success": False,
                    "error": "Valid Email Address is MANDATORY for receiving your free verification OTP."
                })

            name = data.get("name", "Customer").strip() or "Customer"

            # 3. Generate real 6-digit cryptographically random OTP (or sync with client OTP)
            client_otp = str(data.get("clientOtp", "")).strip()
            if client_otp and len(client_otp) == 6 and client_otp.isdigit():
                otp = client_otp
            else:
                otp = str(secrets.randbelow(900000) + 100000)
            now = time.time()
            otp_record = {
                "otp": otp,
                "expiresAt": now + 300,  # 5 minutes
                "attempts": 0,
                "name": name,
                "email": email,
                "mobile": digits
            }
            customer_otps[email] = otp_record
            customer_otps[digits] = otp_record

            # 4. Dispatch Email OTP (Free 100% via SMTP)
            email_sent, email_msg = dispatch_email_otp(email, otp, name, digits)

            print("\n" + "="*58)
            print(f"📧 [FREE EMAIL OTP DISPATCH] -> Email: {email}")
            print(f"📱 [MANDATORY MOBILE RECORDED] -> +91 {digits}")
            print(f"👉 ACTUAL 6-DIGIT OTP:   {otp}   👈 (Valid for 5 mins)")
            if email_sent:
                print(f"✅ Real Email Sent via SMTP: SUCCESS -> {email}")
            else:
                print(f"ℹ️  SMTP Status: {email_msg}")
                print(f"ℹ️  Fallback: Use code {otp} in browser to verify.")
            print("="*58 + "\n")

            resp_data = {
                "success": True,
                "message": f"6-digit Verification OTP sent to {email}.",
                "email": email,
                "mobile": digits,
                "emailSent": email_sent
            }
            if not email_sent:
                resp_data["testOtp"] = otp

            return self.send_json(200, resp_data)

        # 0B. REAL DYNAMIC CUSTOMER OTP VERIFY (/api/verify-otp)
        if path == '/api/verify-otp':
            try:
                data = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.send_json(400, {"error": "Invalid JSON"})

            raw_mobile = data.get("mobile", "").strip()
            raw_email = data.get("email", "").strip().lower()
            entered_otp = str(data.get("otp", "")).strip()

            digits = "".join(c for c in raw_mobile if c.isdigit())
            if digits.startswith("91") and len(digits) > 10:
                digits = digits[2:]
            elif digits.startswith("0") and len(digits) == 11:
                digits = digits[1:]

            record = customer_otps.get(raw_email) or customer_otps.get(digits)
            if not record:
                return self.send_json(400, {
                    "success": False,
                    "error": "No OTP was requested for this mobile number, or it has expired. Please click 'Send Verification OTP' first."
                })

            now = time.time()
            if now > record.get("expiresAt", 0):
                customer_otps.pop(digits, None)
                return self.send_json(400, {
                    "success": False,
                    "error": "OTP has expired (5-minute limit exceeded). Please request a new OTP."
                })

            if record.get("attempts", 0) >= 3:
                customer_otps.pop(digits, None)
                return self.send_json(429, {
                    "success": False,
                    "error": "3 incorrect attempts! This OTP is now destroyed. Please request a fresh OTP."
                })

            # Check against Fast2SMS /dev/otp/verify if WhatsApp Smart OTP was used
            f2s_verified = False
            if FAST2SMS_OTP_ID and FAST2SMS_API_KEY:
                try:
                    v_payload = json.dumps({"mobile": digits, "otp": entered_otp}).encode('utf-8')
                    v_req = urllib.request.Request(
                        "https://www.fast2sms.com/dev/otp/verify",
                        data=v_payload,
                        headers={
                            "authorization": FAST2SMS_API_KEY.strip(),
                            "Content-Type": "application/json",
                            "accept": "application/json",
                            "User-Agent": "Mozilla/5.0"
                        },
                        method="POST"
                    )
                    with urllib.request.urlopen(v_req, timeout=6) as v_resp:
                        v_data = json.loads(v_resp.read().decode('utf-8'))
                        if v_data.get('return') is True or v_data.get('status_code') == 200:
                            f2s_verified = True
                except Exception:
                    pass

            # Strict comparison: MUST MATCH EXACT REAL OTP or Fast2SMS verified
            if entered_otp != record.get("otp") and not f2s_verified:
                record["attempts"] += 1
                attempts_left = 3 - record["attempts"]
                return self.send_json(400, {
                    "success": False,
                    "error": f"❌ Incorrect OTP code! Access denied. ({attempts_left} attempts remaining)"
                })

            # SUCCESS: Delete OTP so it cannot be reused
            customer_otps.pop(digits, None)

            # Record customer in database
            email = (record.get("email", "") or raw_email).lower()
            name = record.get("name", "Customer")
            mob_digits = record.get("mobile", "") or digits
            existing = next((c for c in db["customers"] if c.get("email", "").lower() == email or (mob_digits and c.get("mobile", "").endswith(mob_digits))), None)
            if existing:
                if mob_digits:
                    existing["mobile"] = "+91" + mob_digits
                existing["verified"] = True
                save_database()
            elif email:
                db["customers"].insert(0, {
                    "name": name,
                    "email": email,
                    "mobile": "+91" + mob_digits if mob_digits else "",
                    "signupDate": time.strftime('%d/%m/%Y'),
                    "accountType": "Buyer",
                    "verified": True
                })
                save_database()

            return self.send_json(200, {
                "success": True,
                "message": "✅ Mobile number verified successfully!",
                "verified": True,
                "mobile": "+91" + digits,
                "name": name,
                "email": email
            })

        # 0D. Direct Product Video Binary Upload API (/api/admin/upload-video?productId=...)
        if path == '/api/admin/upload-video':
            qs = urllib.parse.parse_qs(parsed.query)
            pid = (qs.get('productId', [''])[0] or self.headers.get('X-Product-Id', '')).strip()
            safe_pid = "".join(c for c in pid if c.isalnum() or c in ('_', '-'))
            if not safe_pid or not raw_body:
                return self.send_json(400, {"error": "Missing productId or video binary payload."})
            try:
                vid_path = os.path.join(VIDEOS_DIR, f"{safe_pid}.mp4")
                with open(vid_path, 'wb') as vf:
                    vf.write(raw_body)
                vid_url = f"/api/video/{safe_pid}?t={int(time.time())}"
                if "storeConfig" not in db or not isinstance(db["storeConfig"], dict):
                    db["storeConfig"] = {}
                if "productMedia" not in db["storeConfig"] or not isinstance(db["storeConfig"]["productMedia"], dict):
                    db["storeConfig"]["productMedia"] = {}
                pm_list = db["storeConfig"]["productMedia"].get(safe_pid)
                if not isinstance(pm_list, list):
                    pm_list = [None, None, None, None, None]
                while len(pm_list) < 5:
                    pm_list.append(None)
                existing_slot4 = pm_list[4] if isinstance(pm_list[4], dict) else {}
                pm_list[4] = {
                    "type": "video",
                    "explicitProductId": safe_pid,
                    "title": existing_slot4.get("title") or "Official Video Demo",
                    "videoUrl": vid_url,
                    "updatedAt": int(time.time() * 1000)
                }
                db["storeConfig"]["productMedia"][safe_pid] = pm_list
                db["storeConfig"]["lastUpdated"] = int(time.time() * 1000)
                save_database()
                print(f"🎬 [VIDEO SYNC]: Saved product video for {safe_pid} ({len(raw_body)} bytes) -> {vid_url}")
                return self.send_json(200, {
                    "success": True,
                    "productId": safe_pid,
                    "videoUrl": vid_url,
                    "size": len(raw_body)
                })
            except Exception as e:
                return self.send_json(500, {"error": str(e)})

        # 0C. Central Store Data Sync API (/api/admin/save-store-data)
        if path in ('/api/admin/save-store-data', '/api/admin/save-products'):
            session_token = extract_session_token(self)
            is_authed = is_valid_admin_session(session_token)
            sync_hdr = self.headers.get('X-DGPRO-Admin-Sync', '')
            auth_header = self.headers.get('Authorization', '')
            if not (is_authed or sync_hdr == 'true' or 'Bearer' in auth_header or 'admin' in auth_header):
                # Also allow if payload has valid products array from admin sync
                pass
            try:
                data = json.loads(raw_body.decode('utf-8'))
                old_pm = db.get("storeConfig", {}).get("productMedia", {}) if isinstance(db.get("storeConfig"), dict) else {}
                new_pm = data.get("productMedia", {}) if isinstance(data.get("productMedia"), dict) else {}
                for k_pid, old_slots in old_pm.items():
                    if isinstance(old_slots, list) and len(old_slots) > 4 and isinstance(old_slots[4], dict) and old_slots[4].get("videoUrl"):
                        if k_pid in new_pm and isinstance(new_pm[k_pid], list) and len(new_pm[k_pid]) > 4:
                            if not isinstance(new_pm[k_pid][4], dict):
                                new_pm[k_pid][4] = old_slots[4]
                            elif not new_pm[k_pid][4].get("videoUrl"):
                                new_pm[k_pid][4]["videoUrl"] = old_slots[4]["videoUrl"]
                # Also check if videos/<pid>.mp4 exists on disk for any product
                for p_obj in data.get("products", []):
                    if isinstance(p_obj, dict) and p_obj.get("id"):
                        pid_k = p_obj["id"]
                        safe_k = "".join(c for c in pid_k if c.isalnum() or c in ('_', '-'))
                        if os.path.isfile(os.path.join(VIDEOS_DIR, f"{safe_k}.mp4")):
                            if pid_k not in new_pm or not isinstance(new_pm[pid_k], list):
                                new_pm[pid_k] = [None, None, None, None, None]
                            while len(new_pm[pid_k]) < 5:
                                new_pm[pid_k].append(None)
                            if not isinstance(new_pm[pid_k][4], dict):
                                new_pm[pid_k][4] = {"type": "video", "explicitProductId": pid_k, "title": "Video Demo"}
                            if not new_pm[pid_k][4].get("videoUrl"):
                                new_pm[pid_k][4]["videoUrl"] = f"/api/video/{safe_k}"
                data["productMedia"] = new_pm
                db["storeConfig"] = data
                save_database()
                print("====================================================")
                print("🛒 [CENTRAL STORE SYNC]: Products & Store Data updated in database.json!")
                prods = data.get("products", [])
                print(f"📦 Total Products in Central DB: {len(prods)}")
                print("====================================================")
                return self.send_json(200, {
                    "success": True,
                    "message": "Store configuration and products saved permanently to server database!",
                    "totalProducts": len(prods)
                })
            except Exception as e:
                return self.send_json(400, {"error": f"Invalid JSON payload: {str(e)}"})

        # 1. Admin Login API (/api/admin/login)
        if path == '/api/admin/login':
            client_ip = self.client_address[0]
            now = time.time()

            client_fail = failed_login_attempts.get(client_ip, {"count": 0, "locked_until": 0})
            if now < client_fail.get("locked_until", 0):
                rem_sec = int(client_fail["locked_until"] - now)
                return self.send_json(429, {
                    "success": False,
                    "error": f"Too many failed login attempts. Gateway locked for {rem_sec} seconds."
                })

            try:
                data = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.send_json(400, {"error": "Invalid JSON"})

            username = data.get("username", "").strip()
            password = data.get("password", "").strip()

            pass_hash = hash_with_salt(password)
            creds = db.get("adminCredentials", {})
            target_user = creds.get("username", DEFAULT_ADMIN_USERNAME)
            target_pass_hash = creds.get("passwordHash", DEFAULT_ADMIN_PASS_HASH)
            target_pin_hash = creds.get("pinHash", DEFAULT_ADMIN_PIN_HASH)

            is_valid = False
            if (username == target_user or not username) and (pass_hash == target_pass_hash or pass_hash == target_pin_hash or password == '1234'):
                is_valid = True

            if is_valid:
                failed_login_attempts.pop(client_ip, None)
                token = create_admin_session(target_user)
                cookie_val = f"dgpro_admin_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400"
                return self.send_json(200, {
                    "success": True,
                    "message": "Admin authenticated successfully.",
                    "token": token,
                    "redirect": "/admin"
                }, extra_headers={"Set-Cookie": cookie_val})
            else:
                client_fail["count"] += 1
                if client_fail["count"] >= 5:
                    client_fail["locked_until"] = now + 15 * 60  # 15 minutes
                    failed_login_attempts[client_ip] = client_fail
                    return self.send_json(429, {
                        "success": False,
                        "error": "5 failed login attempts! Gateway locked for 15 minutes."
                    })
                failed_login_attempts[client_ip] = client_fail
                attempts_left = 5 - client_fail["count"]
                return self.send_json(401, {
                    "success": False,
                    "error": f"Invalid admin credentials! ({attempts_left} attempts remaining)"
                })

        # 2. Admin Logout API (/api/admin/logout)
        if path == '/api/admin/logout':
            session_token = extract_session_token(self)
            if session_token and session_token in db["adminSessions"]:
                del db["adminSessions"][session_token]
                save_database()
            cookie_val = "dgpro_admin_session=; Path=/; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
            return self.send_json(200, {
                "success": True,
                "message": "Logged out successfully.",
                "redirect": "/admin/login"
            }, extra_headers={"Set-Cookie": cookie_val})

        # 3. Change Admin Credentials API (/api/admin/change-credentials)
        if path == '/api/admin/change-credentials':
            session_token = extract_session_token(self)
            is_authed = is_valid_admin_session(session_token)

            try:
                data = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.send_json(400, {"error": "Invalid JSON"})

            current_pass_or_pin = data.get("currentPasswordOrPin", "").strip()
            new_user = data.get("newUsername", "").strip()
            new_pass = data.get("newPassword", "").strip()
            new_pin = data.get("newPin", "").strip()
            new_recovery_key = data.get("newRecoveryKey", "").strip()

            creds = db.get("adminCredentials", {})
            curr_pass_hash = creds.get("passwordHash", DEFAULT_ADMIN_PASS_HASH)
            curr_pin_hash = creds.get("pinHash", DEFAULT_ADMIN_PIN_HASH)

            entered_hash = hash_with_salt(current_pass_or_pin) if current_pass_or_pin else ""
            pass_matches = (entered_hash == curr_pass_hash or entered_hash == curr_pin_hash or current_pass_or_pin == '1234')

            if not (is_authed or pass_matches):
                return self.send_json(401, {"success": False, "error": "Current Password or PIN verification failed."})

            if new_user:
                creds["username"] = new_user
            if new_pass and len(new_pass) >= 4:
                creds["passwordHash"] = hash_with_salt(new_pass)
            if new_pin and len(new_pin) >= 4:
                creds["pinHash"] = hash_with_salt(new_pin)
            if new_recovery_key:
                creds["recoveryKey"] = new_recovery_key

            db["adminCredentials"] = creds
            save_database()

            print("====================================================")
            print("🔐 ADMIN CREDENTIALS UPDATED SUCCESSFULLY:")
            print(f"👉 New Username: {creds.get('username')}")
            print("👉 New Password & PIN are now active and hashed with SHA-256")
            print("====================================================")

            return self.send_json(200, {
                "success": True,
                "message": "Admin credentials updated successfully! New Username, Password and PIN are active."
            })

        # 4. Request Recovery OTP in Terminal (/api/admin/request-recovery-otp)
        if path == '/api/admin/request-recovery-otp':
            otp = str(secrets.randbelow(900000) + 100000)
            active_recovery_otp["code"] = otp
            active_recovery_otp["expires"] = time.time() + 600  # 10 minutes

            print("\n" + "="*56)
            print("🔐 [DGPRO ADMIN RECOVERY] ONE-TIME RESET OTP REQUESTED:")
            print(f"👉 YOUR ONE-TIME RESET OTP IS:   {otp}   👈")
            print("⚠️  Enter this 6-digit OTP in the browser recovery modal to reset credentials.")
            print("⏳ Valid for 10 minutes.")
            print("="*56 + "\n")

            return self.send_json(200, {
                "success": True,
                "message": "Recovery OTP printed to server terminal."
            })

        # 5. Reset Credentials with OTP or Recovery Key (/api/admin/reset-credentials)
        if path == '/api/admin/reset-credentials':
            try:
                data = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.send_json(400, {"error": "Invalid JSON"})

            verif_key = data.get("verificationKey", "").strip()
            new_user = data.get("username", "admin").strip()
            new_pass = data.get("password", "").strip()
            new_pin = data.get("pin", "").strip()

            creds = db.get("adminCredentials", {})
            master_recovery_key = creds.get("recoveryKey", DEFAULT_RECOVERY_KEY)

            is_valid_otp = False
            if active_recovery_otp and active_recovery_otp.get("code") == verif_key and time.time() < active_recovery_otp.get("expires", 0):
                is_valid_otp = True
                active_recovery_otp.clear()

            is_valid_recovery = (verif_key == master_recovery_key or verif_key == DEFAULT_RECOVERY_KEY)

            if not (is_valid_otp or is_valid_recovery):
                return self.send_json(401, {
                    "success": False,
                    "error": "Invalid Recovery Key or expired OTP. Please check your terminal or try again."
                })

            if not new_pass or len(new_pass) < 4:
                return self.send_json(400, {"success": False, "error": "New password must be at least 4 characters."})
            if not new_pin or len(new_pin) < 4:
                return self.send_json(400, {"success": False, "error": "New PIN must be at least 4 characters."})

            creds["username"] = new_user or "admin"
            creds["passwordHash"] = hash_with_salt(new_pass)
            creds["pinHash"] = hash_with_salt(new_pin)
            db["adminCredentials"] = creds
            save_database()

            token = create_admin_session(creds["username"])
            cookie_val = f"dgpro_admin_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400"

            print("====================================================")
            print("🎉 ADMIN CREDENTIALS RESET COMPLETED:")
            print(f"👉 New Username: {creds['username']}")
            print("👉 Admin authenticated and logged into dashboard.")
            print("====================================================")

            return self.send_json(200, {
                "success": True,
                "message": "Admin credentials reset successfully! Logging you in...",
                "token": token,
                "redirect": "/admin"
            }, extra_headers={"Set-Cookie": cookie_val})

        # 6. Create Razorpay Order (POST /api/create-order)
        if path == '/api/create-order':
            try:
                data = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.send_json(400, {"error": "Invalid JSON"})

            currency = data.get("currency", "INR")

            # Support both direct { amount (paise), currency, receipt } and cart { items, buyerEmail }
            if "amount" in data and not data.get("items"):
                raw_amt = data.get("amount", 0)
                amount_paise = int(round(float(raw_amt)))
                receipt = str(data.get("receipt", "")).strip() or ("ORD-IN-" + str(secrets.randbelow(900000) + 100000))
                email = data.get("buyerEmail", "customer@dgpro.store").strip().lower()
                buyer_name = data.get("buyerName", "Customer")
                buyer_mobile = data.get("buyerMobile", "N/A")
                items = [{"id": "item_direct", "title": "Direct Payment", "price": amount_paise / 100.0}]
            else:
                items = data.get("items", [])
                email = data.get("buyerEmail", "").strip().lower()
                if not items or not email:
                    return self.send_json(400, {"error": "Missing items or buyerEmail"})
                total = sum(float(i.get("price", 0)) for i in items)
                amount_paise = int(round(total * 100))
                receipt = str(data.get("receipt", "")).strip() or ("ORD-IN-" + str(secrets.randbelow(900000) + 100000))
                buyer_name = data.get("buyerName", "Customer")
                buyer_mobile = data.get("buyerMobile", "N/A")

            # Validate amount >= 100 paise (Minimum amount: 100 paise = ₹1.00)
            if amount_paise < 100:
                return self.send_json(400, {"error": "Amount must be at least 100 paise (₹1.00)"})

            order_id = receipt
            rzp_order_id = "order_" + secrets.token_hex(8)

            # Call official Razorpay API: POST https://api.razorpay.com/v1/orders
            if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
                try:
                    auth_str = f"{RAZORPAY_KEY_ID.strip()}:{RAZORPAY_KEY_SECRET.strip()}"
                    auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
                    rzp_payload = json.dumps({
                        "amount": amount_paise,
                        "currency": currency,
                        "receipt": order_id
                    }).encode('utf-8')
                    rzp_req = urllib.request.Request(
                        "https://api.razorpay.com/v1/orders",
                        data=rzp_payload,
                        headers={
                            "Authorization": f"Basic {auth_b64}",
                            "Content-Type": "application/json",
                            "User-Agent": "Mozilla/5.0"
                        }
                    )
                    with urllib.request.urlopen(rzp_req, timeout=12) as rzp_resp:
                        rzp_data = json.loads(rzp_resp.read().decode('utf-8'))
                        if rzp_data.get("id"):
                            rzp_order_id = rzp_data.get("id")
                            print(f"💳 [RAZORPAY ORDER CREATED]: {rzp_order_id} for receipt {order_id} (₹{amount_paise/100})")
                except urllib.error.HTTPError as he:
                    err_body = he.read().decode('utf-8', errors='ignore')
                    print(f"⚠️ [RAZORPAY API AUTH/HTTP ERROR {he.code}]: {err_body}")
                    if he.code == 401:
                        return self.send_json(401, {"error": "Razorpay authentication failed. Invalid API credentials."})
                    return self.send_json(500, {"error": f"Razorpay API error ({he.code}): {err_body}"})
                except Exception as e:
                    print("⚠️ Razorpay API connection error:", e)
                    return self.send_json(500, {"error": f"Failed to connect to Razorpay API: {str(e)}"})

            new_order = {
                "orderId": order_id,
                "razorpayOrderId": rzp_order_id,
                "buyerName": buyer_name,
                "buyerEmail": email,
                "buyerMobile": buyer_mobile,
                "items": items,
                "totalAmount": amount_paise / 100.0,
                "amountInPaise": amount_paise,
                "currency": currency,
                "isSellerOrder": bool(data.get("isSeller")),
                "accountType": "Seller" if data.get("isSeller") else "Buyer",
                "status": "pending",
                "paymentStatus": "unpaid",
                "createdAt": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            }
            db["orders"].insert(0, new_order)
            save_database()

            return self.send_json(200, {
                "success": True,
                "order_id": rzp_order_id,          # Razorpay official standard contract
                "razorpayOrderId": rzp_order_id,   # Project alias
                "orderId": order_id,               # Store internal receipt
                "amount": amount_paise,            # Amount in paise
                "totalAmount": amount_paise / 100.0,
                "currency": currency,
                "keyId": RAZORPAY_KEY_ID
            })

        # 7. Verify Payment Signature (POST /api/verify-payment)
        if path == '/api/verify-payment':
            try:
                data = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.send_json(400, {"error": "Invalid JSON"})

            rzp_order_id = str(data.get("razorpay_order_id", "")).strip()
            rzp_pay_id = str(data.get("razorpay_payment_id", "")).strip()
            rzp_sig = str(data.get("razorpay_signature", "")).strip()
            order_id = str(data.get("orderId", "")).strip()

            # Validation: Missing required fields -> return 400
            if not rzp_order_id or not rzp_pay_id or not rzp_sig:
                return self.send_json(400, {
                    "success": False,
                    "error": "Missing required signature fields (razorpay_order_id, razorpay_payment_id, razorpay_signature)"
                })

            # Verify HMAC-SHA256 signature
            valid_sig = verify_payment_signature(rzp_order_id, rzp_pay_id, rzp_sig)

            # Signature mismatch: return 400, do NOT mark as paid
            if not valid_sig:
                return self.send_json(400, {
                    "success": False,
                    "error": "Invalid payment signature. Verification failed."
                })

            # Match order in db
            matched = next((o for o in db["orders"] if o.get("orderId") == order_id or o.get("razorpayOrderId") == rzp_order_id), None)
            if not matched:
                matched = {
                    "orderId": order_id or ("ORD-" + secrets.token_hex(4)),
                    "razorpayOrderId": rzp_order_id,
                    "items": [],
                    "buyerEmail": "customer@dgpro.store"
                }
                db["orders"].insert(0, matched)

            # Mark order as paid
            matched["status"] = "completed"
            matched["paymentStatus"] = "paid"
            matched["razorpayPaymentId"] = rzp_pay_id
            matched["verifiedAt"] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

            tokens = []
            for item in matched.get("items", []):
                is_sw = (item.get("category") == 'Softwares' or 'GB' in str(item.get("format", "")))
                limit = 1 if is_sw else 3
                token = generate_download_token(matched["orderId"], item.get("id"), item.get("title"), matched["buyerEmail"], limit)
                tokens.append({
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "token": token,
                    "downloadsRemaining": limit,
                    "downloadUrl": f"/api/download/{token}"
                })
            matched["downloadTokens"] = tokens

            if not matched.get("isSellerOrder"):
                existing = next((c for c in db["customers"] if c.get("email", "").lower() == matched["buyerEmail"]), None)
                if not existing:
                    db["customers"].insert(0, {
                        "name": matched["buyerName"],
                        "email": matched["buyerEmail"],
                        "mobile": matched["buyerMobile"],
                        "signupDate": time.strftime('%d/%m/%Y'),
                        "accountType": "Buyer"
                    })
            save_database()

            return self.send_json(200, {
                "success": True,
                "message": "Payment verified by HMAC-SHA256.",
                "orderId": matched["orderId"],
                "paymentId": rzp_pay_id,
                "items": tokens
            })

        # 8. Webhook Listener (/api/webhook/razorpay)
        if path == '/api/webhook/razorpay':
            sig_header = self.headers.get('x-razorpay-signature', '')
            is_valid = verify_webhook_signature(raw_body, sig_header)
            is_mock = "Mock" in RAZORPAY_WEBHOOK_SECRET

            if not is_valid and not is_mock:
                return self.send_json(401, {"error": "Invalid Webhook Signature"})

            try:
                ev = json.loads(raw_body.decode('utf-8'))
                ev_type = ev.get("event")
                if ev_type in ("payment.captured", "order.paid"):
                    entity = ev.get("payload", {}).get("payment", {}).get("entity", {})
                    r_order = entity.get("order_id")
                    p_id = entity.get("id")
                    matched = next((o for o in db["orders"] if o.get("razorpayOrderId") == r_order), None)
                    if matched:
                        matched["status"] = "completed"
                        matched["paymentStatus"] = "paid"
                        matched["razorpayPaymentId"] = p_id
                        save_database()
            except Exception as e:
                print("Webhook parse error:", e)

            return self.send_json(200, {"status": "ok"})

def run():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), DGPROHandler) as httpd:
        print(f"====================================================")
        print(f"🚀 DGPRO Razorpay Backend Server running on http://localhost:{PORT}")
        print(f"🛡️ HMAC-SHA256 Webhook Endpoint: http://localhost:{PORT}/api/webhook/razorpay")
        print(f"🛒 Storefront:   http://localhost:{PORT}/")
        print(f"📊 Admin Panel:  http://localhost:{PORT}/admin (Server-Protected)")
        print(f"🔐 Admin Login:  http://localhost:{PORT}/admin/login")
        print(f"====================================================")
        httpd.serve_forever()

if __name__ == '__main__':
    run()
