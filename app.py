from flask import Flask, request, jsonify, Response
import hmac
import hashlib
import requests
import string
import random
import json
import codecs
import time
import os
import base64
import threading
import itertools
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==============================================================================
# 🔐 GARENA CONSTANTS & KEYS (OB54)
# ==============================================================================
REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", 
    "TH": "th", "BD": "bn", "PK": "ur", "TW": "zh", 
    "CIS": "ru", "SAC": "es", "BR": "pt"
}

HEX_KEY_STR = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = bytes.fromhex(HEX_KEY_STR)

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

DEVICE_POOL = [
    {"model": "SM-G973F", "brand": "Samsung", "android": "12", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G973F Build/SP1A.210812.016)"},
    {"model": "SM-G998B", "brand": "Samsung", "android": "13", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 13; SM-G998B Build/TP1A.220624.014)"},
    {"model": "M2101K7AG", "brand": "Xiaomi", "android": "12", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)"},
    {"model": "LE2121", "brand": "OnePlus", "android": "13", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 13; LE2121 Build/TP1A.220905.001)"},
]

# ==============================================================================
# 🌐 INTEGRATED PROXY MANAGER ENGINE
# ==============================================================================
class ProxyEntry:
    def __init__(self, proxy_str: str):
        self.raw = proxy_str.strip()
        if not self.raw.startswith(("http://", "https://", "socks4://", "socks5://")):
            self.url = f"http://{self.raw}"
        else:
            self.url = self.raw
        self.cooldown_until = 0.0
        self.failures = 0
        self.lock = threading.Lock()

    @property
    def is_available(self) -> bool:
        with self.lock:
            return time.time() >= self.cooldown_until

    def set_cooldown(self, seconds: float = 60.0):
        with self.lock:
            self.failures += 1
            self.cooldown_until = time.time() + (seconds * min(self.failures, 5))

    def reset_failure(self):
        with self.lock:
            self.failures = 0

    @property
    def requests_dict(self):
        return {"http": self.url, "https": self.url}


class ProxyManager:
    def __init__(self, proxy_file="proxies.txt"):
        self.proxies = []
        self.counter = itertools.count()
        self.lock = threading.Lock()
        self.load_proxies(proxy_file)

    def load_proxies(self, filepath="proxies.txt"):
        loaded = []
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            loaded.append(ProxyEntry(line))
            except Exception as e:
                print(f"[PROXY] Error loading {filepath}: {e}")
        
        with self.lock:
            self.proxies = loaded
            print(f"[PROXY] Total {len(self.proxies)} proxies loaded into active pool.")

    def select_proxy(self) -> ProxyEntry:
        with self.lock:
            if not self.proxies:
                return None
            available = [p for p in self.proxies if p.is_available]
            if not available:
                # Fallback: choose random if all in cooldown
                return random.choice(self.proxies)
            # Round-robin selection
            idx = next(self.counter) % len(available)
            return available[idx]


# Global Proxy Engine Instance
PROXY_MANAGER = ProxyManager("proxies.txt")

# ==============================================================================
# 🛠️ PROTOBUF & CRYPTOGRAPHY HELPERS
# ==============================================================================
def encode_varint(n):
    if n < 0: return b''
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n: byte |= 0x80
        result.append(byte)
        if not n: break
    return bytes(result)

def create_proto_field(field_num, value):
    if isinstance(value, dict):
        nested = create_proto_field(field_num, value)
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(nested)) + nested
    elif isinstance(value, int):
        header = (field_num << 3) | 0
        return encode_varint(header) + encode_varint(value)
    elif isinstance(value, (str, bytes)):
        encoded_val = value.encode() if isinstance(value, str) else value
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(encoded_val)) + encoded_val
    return b''

def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())

def aes_encrypt(data):
    if isinstance(data, str):
        data = bytes.fromhex(data)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def generate_random_name(base="ARIYAN"):
    exp_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    num = random.randint(1000, 9999)
    exponent = ''.join(exp_digits[d] for d in f"{num:04d}")
    return f"{base}{exponent}"

def generate_custom_password(prefix="ARIYAN"):
    rand_part = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"{prefix}_ARIYAN_{rand_part}"

# ==============================================================================
# 🚀 STICKY SESSION ACCOUNT GENERATOR
# ==============================================================================
def create_single_account_sticky(region="BD", name_base="ARIYAN", password_prefix="ARIYAN"):
    """Creates an account bound to a single sticky proxy throughout the cycle."""
    session = requests.Session()
    session.verify = False
    
    # 1. Acquire Proxy from Pool
    proxy_entry = PROXY_MANAGER.select_proxy()
    if proxy_entry:
        session.proxies.update(proxy_entry.requests_dict)

    device = random.choice(DEVICE_POOL)
    session.headers.update({
        "User-Agent": device["user_agent"],
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "Keep-Alive"
    })

    password = generate_custom_password(password_prefix)

    # Step 1: Register UID
    uid = None
    try:
        url_reg = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
        payload_reg = json.dumps({"app_id": 100067, "client_type": 2, "password": password, "source": 2}, separators=(',', ':'))
        sig = hmac.new(API_KEY, payload_reg.encode(), hashlib.sha256).hexdigest()
        headers_reg = {
            "Authorization": f"Signature {sig}",
            "Content-Type": "application/json; charset=utf-8"
        }
        res = session.post(url_reg, headers=headers_reg, data=payload_reg, timeout=4)
        if res.status_code == 200 and res.json().get("code") == 0:
            uid = res.json().get("data", {}).get("uid")
    except Exception:
        pass

    if not uid:
        try:
            res = session.post("https://100067.connect.garena.com/oauth/guest/register", data={"password": password, "client_id": "100067"}, timeout=4)
            if res.status_code == 200:
                uid = res.json().get("uid")
        except Exception:
            if proxy_entry: proxy_entry.set_cooldown(30)
            return None

    if not uid:
        if proxy_entry: proxy_entry.set_cooldown(30)
        return None

    # Step 2: Token Grant
    access_token = None
    open_id = None
    try:
        body = {
            "uid": str(uid),
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": HEX_KEY_STR,
            "client_id": "100067"
        }
        res = session.post("https://100067.connect.garena.com/oauth/guest/token/grant", data=body, timeout=4)
        if res.status_code == 200:
            data = res.json()
            access_token = data.get("access_token")
            open_id = data.get("open_id")
    except Exception:
        if proxy_entry: proxy_entry.set_cooldown(30)
        return None

    if not access_token or not open_id:
        if proxy_entry: proxy_entry.set_cooldown(30)
        return None

    # Step 3: Major Register
    try:
        name = generate_random_name(name_base)
        keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 
                     0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
        encoded = "".join(chr(ord(open_id[i]) ^ keystream[i % len(keystream)]) for i in range(len(open_id)))
        field = encoded.encode('latin1')

        lang_code = REGION_LANG.get(region.upper(), "bn")
        payload = {
            1: name, 2: access_token, 3: open_id, 5: 102000007, 
            6: 4, 7: 1, 13: 1, 14: field, 15: lang_code, 16: 1, 17: 1
        }
        encrypted_payload = aes_encrypt(build_proto(payload))

        host_mr = "https://loginbp.common.ggbluefox.com/MajorRegister" if region.upper() in ["ME", "TH"] else "https://loginbp.ggpolarbear.com/MajorRegister"
        headers_mr = {
            "Content-Type": "application/x-www-form-urlencoded",
            "ReleaseVersion": "OB54",
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 12; ASUS_I005DA)",
            "X-GA": "v1 1", "X-Unity-Version": "1.126.1"
        }
        session.post(host_mr, headers=headers_mr, data=encrypted_payload, timeout=5)
    except Exception:
        pass

    # Step 4: Major Login
    jwt_token = ""
    account_id = "N/A"
    try:
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang_code.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        payload = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        payload = payload.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())

        host_ml = "https://loginbp.common.ggbluefox.com/MajorLogin" if region.upper() in ["ME", "TH"] else "https://loginbp.ggpolarbear.com/MajorLogin"
        resp = session.post(host_ml, headers=headers_mr, data=aes_encrypt(payload), timeout=5)

        if resp.status_code == 200:
            text = resp.text
            jwt_start = text.find("eyJ")
            if jwt_start != -1:
                raw_jwt = text[jwt_start:]
                dot2 = raw_jwt.find(".", raw_jwt.find(".") + 1)
                if dot2 != -1:
                    jwt_token = raw_jwt[:dot2 + 44]
                    parts = jwt_token.split('.')
                    if len(parts) >= 2:
                        p_b64 = parts[1] + '=' * ((4 - len(parts[1]) % 4) % 4)
                        data = json.loads(base64.urlsafe_b64decode(p_b64).decode('utf-8', errors='ignore'))
                        account_id = str(data.get('account_id') or data.get('external_id', 'N/A'))
    except Exception:
        pass

    # Step 5: Choose Region & Guide
    if jwt_token and region.upper() != "BR":
        try:
            proto_cr = build_proto({1: "RU" if region.upper() == "CIS" else region.upper()})
            headers_bind = {
                'Authorization': f"Bearer {jwt_token}",
                'ReleaseVersion': "OB54",
                'Content-Type': "application/x-www-form-urlencoded"
            }
            session.post("https://loginbp.ggpolarbear.com/ChooseRegion", data=aes_encrypt(proto_cr), headers=headers_bind, timeout=3)
            proto_bg = build_proto({1: 3})
            session.post("https://clientbp.ggpolarbear.com/ActiveBeginnerGuide", data=aes_encrypt(proto_bg), headers=headers_bind, timeout=3)
        except Exception:
            pass

    if uid and (jwt_token or access_token):
        if proxy_entry: proxy_entry.reset_failure()
        return {
            "uid": str(uid),
            "password": password,
            "name": name,
            "region": region,
            "account_id": account_id,
            "token": jwt_token if jwt_token else access_token,
            "proxy_used": proxy_entry.raw if proxy_entry else "DIRECT"
        }

    if proxy_entry: proxy_entry.set_cooldown(30)
    return None

# ==============================================================================
# 🌐 API ENDPOINTS (High-Speed Parallel Pool)
# ==============================================================================
@app.route('/gen', methods=['GET'])
def generate_accounts():
    name = request.args.get('name', 'ARIYAN')
    count = request.args.get('count', '1')
    region = request.args.get('region', 'BD').upper()
    prefix = request.args.get('password_prefix', 'ARIYAN')

    try:
        count = int(count)
        count = max(1, min(count, 20))
    except:
        count = 1

    if region not in REGION_LANG:
        region = "BD"

    results = []
    # Parallel thread execution across separate rotating proxies
    workers_count = max(15, count * 3)
    with ThreadPoolExecutor(max_workers=workers_count) as executor:
        futures = [executor.submit(create_single_account_sticky, region, name, prefix) for _ in range(workers_count)]
        for future in as_completed(futures):
            res = future.result()
            if res and res.get('uid'):
                results.append(res)
                if len(results) >= count:
                    break

    return jsonify({
        "success": True,
        "total_requested": count,
        "total_created": len(results),
        "accounts": results,
        "region": region,
        "message": f"Successfully generated {len(results)} accounts for {name}"
    })

@app.route('/')
def home():
    # Direct Root Hit: Returns 1 account immediately
    acc = None
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(create_single_account_sticky, "BD", "ARIYAN", "ARIYAN") for _ in range(10)]
        for future in as_completed(futures):
            res = future.result()
            if res and res.get('uid'):
                acc = res
                break

    if acc:
        return jsonify({"status": "success", "account": acc})
    return jsonify({"status": "error", "message": "Server busy, please retry."}), 503

@app.route('/proxies')
def proxy_stats():
    available = len([p for p in PROXY_MANAGER.proxies if p.is_available])
    return jsonify({
        "total_proxies": len(PROXY_MANAGER.proxies),
        "available_proxies": available,
        "strategy": "Round Robin Sticky Session"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "ARIYAN Ultimate Proxy-Gen Engine", "version": "12.1"})

# ========== WSGI ENTRY POINT ==========
def application(environ, start_response):
    return app(environ, start_response)

if __name__ == '__main__':
    print("🚀 ARIYAN Ultra-Fast Proxy Engine Running on port 8080...")
    app.run(host='0.0.0.0', port=8080, debug=False)
