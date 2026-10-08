# ═══════════════════════════════════════════════════════════════
#  ARIYAN API — FREE FIRE BD ACCOUNT GENERATOR (OB55) — v13 FINAL
#  Flask version — Vercel/PythonAnywhere/Render compatible
# ═══════════════════════════════════════════════════════════════

from flask import Flask, request, jsonify
import hmac, hashlib, requests, string, random, json, codecs, time
import os, base64, threading, re, uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════
#  CONSTANTS (OB55)
# ═══════════════════════════════════════════════════════════════
RELEASE_VERSION = "OB55"
UNITY_VERSION   = "2018.4.12f1"
CLIENT_VERSION  = "1.132.6"
CLIENT_VER_CODE = "2019121227"

API_BASE   = "https://100067.connect.garena.com"
MAJOR_BASE = "https://loginbp.ggpolarbear.com"
CLIENT_BASE = "https://clientbp.ggpolarbear.com"

HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = bytes.fromhex(HEX_KEY)

AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

# BD region — language MUST be "en" (bn rejects)
REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi",
    "TH": "th", "BD": "en", "PK": "ur", "TW": "zh",
    "CIS": "ru", "SAC": "es", "BR": "pt"
}

# BD-specific
BD_CARRIERS = ["Grameenphone", "Robi", "Banglalink", "Teletalk", "Airtel"]
BD_IP_PREFIXES = ["103.230.", "103.108.", "103.148.", "103.87.",
                  "119.30.", "119.148.", "202.134.", "202.4.",
                  "103.4.", "103.84.", "103.99.", "27.147."]
BD_DEVICES = [
    "SM-A515F", "SM-A125F", "SM-M215F", "Redmi 9A",
    "Redmi Note 10", "Realme C15", "Vivo Y20", "Oppo A15",
    "Infinix Hot 10", "Walton Primo", "Symphony Z35", "Lava Z2",
]
BD_ANDROID = ["9", "10", "11", "12"]

DEVICE_POOL = [
    {"model": "SM-A515F", "ua": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A515F Build/RP1A.200720.012)"},
    {"model": "SM-G998B", "ua": "Dalvik/2.1.0 (Linux; U; Android 13; SM-G998B Build/TP1A.220624.014)"},
    {"model": "Redmi Note 10", "ua": "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)"},
    {"model": "Realme C15", "ua": "Dalvik/2.1.0 (Linux; U; Android 10; RMX2180 Build/QP1A.190711.020)"},
    {"model": "Vivo Y20", "ua": "Dalvik/2.1.0 (Linux; U; Android 11; V2027 Build/RP1A.200720.012)"},
    {"model": "Oppo A15", "ua": "Dalvik/2.1.0 (Linux; U; Android 10; CPH2185 Build/QP1A.190711.020)"},
]

thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        thread_local.session.verify = False
        thread_local.session.timeout = 10
        dev = random.choice(DEVICE_POOL)
        thread_local.session.headers.update({
            'User-Agent': dev['ua'],
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    return thread_local.session

# ═══════════════════════════════════════════════════════════════
#  PROTO HELPERS
# ═══════════════════════════════════════════════════════════════
def encode_varint(n):
    if n < 0: return b''
    out = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def create_proto_field(field_num, value):
    if isinstance(value, int):
        return encode_varint((field_num << 3) | 0) + encode_varint(value)
    if isinstance(value, (str, bytes)):
        ev = value.encode() if isinstance(value, str) else value
        return encode_varint((field_num << 3) | 2) + encode_varint(len(ev)) + ev
    return b''

def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())

def aes_encrypt_bytes(data: bytes) -> bytes:
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(data, AES.block_size))

def aes_encrypt_hex(hex_data: str) -> bytes:
    return aes_encrypt_bytes(bytes.fromhex(hex_data))

def encode_open_id_xor(open_id: str) -> bytes:
    keystream = [
        0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,
        0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
        0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,
        0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,
    ]
    ob = open_id.encode('utf-8')
    return bytes([ob[i] ^ keystream[i % 32] for i in range(len(ob))])

def random_bd_ip():
    p = random.choice(BD_IP_PREFIXES)
    return p + f"{random.randint(1,254)}.{random.randint(1,254)}" if p.count('.') == 2 else p + f"{random.randint(1,254)}"

def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            b = parts[1] + '=' * ((4 - len(parts[1]) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(b).decode('utf-8', errors='ignore'))
    except Exception:
        pass
    return {}

# ═══════════════════════════════════════════════════════════════
#  FIELD_22 (OB55 mandatory)
# ═══════════════════════════════════════════════════════════════
FIELD_22 = bytes.fromhex(
    "4747524501010100620200001052aa0d669c6a368f08338060d2ee0690053af84a41edcd3558556ec10f24f4"
    "6c93ac64ca41a16732c46a2cb071246a79b8929032f9e1b6f4ef331bd53cabf29b09b97349a46e9863c0314e"
    "1a0d80819fef8aabf03876b3d037db354a7ccb5c1bce96411fb3753f6f50e44c69c4ed617fa30efb8ffc0517"
    "ff2f636739be1f304d999cfd6fd48bf69454199794c3dc88f55a4bdbd66534d5a061359cdfd1fb680cd37918"
    "df9fdb3cf7d80067b0a3506c90063cf62b2ccec11e23913a2fd7c4ef091331967bb518a5ad1e551146b90821"
    "be800883abadde39d6c80a5d798611466c748f075481806c5842ce45e6bd4e3368ec08fe2ec41ceb880cd862"
    "49eb71693f79f0bccf9e590c3fae12519fe08c7a1905d0927690109e0df28574bb14847225db1a59230e6662"
    "ed7730e15ff9a6c815cb41b420edeada735a4b03e181037c37c2c850257311df2f07b0a56e759372cbd0268e"
    "3f13a292ee4373e38ab5096e0342a5e0d7fec6da2bbc265d74baadd2b24ee4f74862f82c21d6694bac53f8ce"
    "80312a30068a6276a641c19b11d0305c6fe2f531ac7de578b29f543697f5c73663e6f23aa15277b6122dcd4d"
    "4171e38f9ac0b173f39c58416a16c5c1f4a35acd065ce78f449cf538a249339e763272d458e4ed86c976591a"
    "9c066b3a37111e44091eb6b5a795249f3e5145db022a6055f2cc675936391312f688f89627845df222a91156"
    "555225be36f9714a0ba50246d0f003bda3c9c1292ab73b4f79635ddd023218eda93a302d79e023404c143965"
    "44a930b98ed54771aca7fec10d095587685b473e81a9619764fad9256529dcd6e911f4f4629612287d4ee3ec"
    "5389f6ec4ec020b0e2aac017232a9197be9e46239ce690fe5d4872b2e98e651510c971667f3aca8b59f3e9d5"
    "0e43"
)

# ═══════════════════════════════════════════════════════════════
#  NAME SANITIZER
# ═══════════════════════════════════════════════════════════════
DIRTY = {'admin','mod','freefire','ff','garena','bot','fuck','sex','porn',
         'xxx','dick','ass','gay','bitch','kill','death','hate','terror',
         'bomb','gun','drug','scam','hack','cheat','official','support'}

def sanitize_name(name):
    if not name: name = "Ariyan"
    c = ''.join(ch for ch in name if ch.isalnum())
    low = c.lower()
    for w in DIRTY:
        if w in low:
            c = re.sub(re.escape(w),
                       ''.join(random.choice('0123456789') for _ in range(len(w))),
                       c, flags=re.IGNORECASE)
            low = c.lower()
    c = re.sub(r'(.)\1{2,}', r'\1\1', c)
    if c and not c[0].isalpha():
        c = random.choice(string.ascii_letters) + c
    if len(c) < 4:
        c += ''.join(random.choice(string.digits) for _ in range(4 - len(c)))
    return c[:12]

def generate_name(prefix="Ariyan"):
    p = sanitize_name(prefix or "Ariyan")
    suf = ''.join(random.choice(string.digits) for _ in range(max(1, 12 - len(p))))
    return (p + suf)[:12]

def generate_password(prefix="ARIYAN"):
    return f"{prefix}_{''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))}"

# ═══════════════════════════════════════════════════════════════
#  STEP 1 — GUEST REGISTER
# ═══════════════════════════════════════════════════════════════
def guest_register(password):
    session = get_session()
    try:
        payload = json.dumps({"app_id": 100067, "client_type": 2,
                              "password": password, "source": 2}, separators=(',', ':'))
        sig = hmac.new(API_KEY, payload.encode(), hashlib.sha256).hexdigest()
        headers = {
            "Authorization": f"Signature {sig}",
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "Connection": "Keep-Alive",
        }
        r = session.post(f"{API_BASE}/api/v2/oauth/guest:register",
                         headers=headers, data=payload, timeout=10, verify=False)
        if r.status_code != 200:
            return None
        j = r.json()
        if j.get("code") != 0:
            return None
        return j["data"]["uid"]
    except Exception:
        return None

# ═══════════════════════════════════════════════════════════════
#  STEP 2 — TOKEN GRANT
# ═══════════════════════════════════════════════════════════════
def token_grant(uid, password):
    session = get_session()
    try:
        payload = json.dumps({
            "client_id": 100067,
            "client_secret": HEX_KEY,
            "client_type": 2,
            "password": password,
            "response_type": "token",
            "uid": str(uid),
        }, separators=(',', ':'))
        sig = hmac.new(API_KEY, payload.encode(), hashlib.sha256).hexdigest()
        headers = {
            "Authorization": f"Signature {sig}",
            "Content-Type": "application/json; charset=utf-8",
            "Connection": "Keep-Alive",
        }
        r = session.post(f"{API_BASE}/api/v2/oauth/guest/token:grant",
                         headers=headers, data=payload, timeout=10, verify=False)
        if r.status_code != 200:
            return None
        j = r.json()
        if j.get("code") != 0:
            return None
        return j["data"]["access_token"], j["data"]["open_id"]
    except Exception:
        return None

# ═══════════════════════════════════════════════════════════════
#  STEP 3 — MAJOR REGISTER (BD, OB55)
# ═══════════════════════════════════════════════════════════════
def major_register(name, access_token, open_id, lang="en"):
    session = get_session()
    try:
        reg_fields = {
            1: name,
            2: access_token,
            3: open_id,
            5: 102000007,
            6: 4,
            7: 1,
            13: 1,
            14: encode_open_id_xor(open_id),
            15: lang,                # BD → "en"
            16: 1,
            22: FIELD_22,            # OB55 mandatory
        }
        encrypted = aes_encrypt_bytes(build_proto(reg_fields))
        headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept-Encoding": "deflate, gzip",
            "X-GA-SV": "1789535859",
            "Authorization": f"Bearer {access_token}",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASE_VERSION,
            "Content-Type": "application/octet-stream",
            "X-Unity-Version": UNITY_VERSION,
            "Host": "loginbp.ggpolarbear.com",
        }
        r = session.post(f"{MAJOR_BASE}/MajorRegister",
                         headers=headers, data=encrypted, timeout=15, verify=False)
        return r.status_code == 200
    except Exception:
        return False

# ═══════════════════════════════════════════════════════════════
#  STEP 4 — MAJOR LOGIN (dynamic proto, BD-aware)
# ═══════════════════════════════════════════════════════════════
def build_major_login_proto(open_id, access_token, region="BD"):
    dev = random.choice(BD_DEVICES)
    av = random.choice(BD_ANDROID)
    carrier = random.choice(BD_CARRIERS)
    ip = random_bd_ip()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    api_level = {"9": 28, "10": 29, "11": 30, "12": 31}.get(av, 28)
    did = f"Google|{uuid.uuid4()}"

    fields = {
        3: now, 4: "free fire", 5: 4,
        7: CLIENT_VERSION, 8: CLIENT_VER_CODE,
        9: f"Android OS {av} / API-{api_level}",
        10: "Handheld", 11: dev,
        12: 1280, 13: 720, 14: "240",
        15: "ARMv7 VFPv3 NEON | 2400 | 4",
        16: random.choice([5951, 6000, 6100]),
        17: random.choice(["Adreno 610", "Mali-G72", "PowerVR GE8320"]),
        18: "OpenGL ES 3.1 v1.46",
        19: did, 20: ip, 21: "en",
        22: open_id, 23: "4", 24: "Handheld",
        25: dev, 26: region.upper(),
        29: access_token, 30: 1,
        41: carrier, 42: "WIFI",
        92: random.choice([19788, 20000, 21000]),
        93: "android_max",
        97: 1, 98: 1, 99: "4", 100: "4",
        104: 77149, 105: 1,
    }
    return aes_encrypt_bytes(build_proto(fields))

def major_login(open_id, access_token, region="BD"):
    session = get_session()
    try:
        encrypted = build_major_login_proto(open_id, access_token, region)
        headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept-Encoding": "deflate, gzip",
            "X-GA-SV": "1789535859",
            "Authorization": f"Bearer {access_token}",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASE_VERSION,
            "Content-Type": "application/octet-stream",
            "X-Unity-Version": UNITY_VERSION,
            "Host": "loginbp.ggpolarbear.com",
        }
        r = session.post(f"{MAJOR_BASE}/MajorLogin",
                         headers=headers, data=encrypted, timeout=15, verify=False)
        if r.status_code != 200:
            return {"account_id": "N/A", "jwt_token": ""}

        m = re.search(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", r.content)
        if not m:
            return {"account_id": "N/A", "jwt_token": ""}

        jwt_token = m.group(0).decode('utf-8', errors='ignore')
        jd = decode_jwt(jwt_token)
        acc_id = jd.get("account_id") or jd.get("external_id")
        return {"account_id": str(acc_id) if acc_id else "N/A", "jwt_token": jwt_token}
    except Exception:
        return {"account_id": "N/A", "jwt_token": ""}

# ═══════════════════════════════════════════════════════════════
#  STEP 5 — ChooseRegion BD
# ═══════════════════════════════════════════════════════════════
def choose_region_bd(jwt_token):
    if not jwt_token:
        return
    try:
        session = get_session()
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 12)",
            "Authorization": f"Bearer {jwt_token}",
            "ReleaseVersion": RELEASE_VERSION,
            "Content-Type": "application/octet-stream",
        }
        session.post(f"{MAJOR_BASE}/ChooseRegion",
                     data=aes_encrypt_bytes(build_proto({1: "BD"})),
                     headers=headers, timeout=10, verify=False)
        session.post(f"{CLIENT_BASE}/ActiveBeginnerGuide",
                     data=aes_encrypt_bytes(build_proto({1: 3})),
                     headers=headers, timeout=10, verify=False)
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════
#  FULL FLOW — CREATE ONE ACCOUNT
# ═══════════════════════════════════════════════════════════════
def create_account(region="BD", name_prefix="ARIYAN", password_prefix="ARIYAN"):
    try:
        password = generate_password(password_prefix)
        uid = guest_register(password)
        if not uid:
            return None

        tok = token_grant(uid, password)
        if not tok:
            return None
        access_token, open_id = tok

        name = generate_name(name_prefix)
        lang = REGION_LANG.get(region.upper(), "en")

        ok = major_register(name, access_token, open_id, lang)
        if not ok:
            return None

        login = major_login(open_id, access_token, region)
        acc_id = login.get("account_id", "N/A")
        jwt = login.get("jwt_token", "")

        if acc_id == "N/A":
            return None

        # Bind BD region
        if jwt:
            choose_region_bd(jwt)

        return {
            "status": "success",
            "region": region.upper(),
            "name": name,
            "uid": str(uid),
            "password": password,
            "account_id": acc_id,
            "jwt_token": jwt,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception:
        return None

# ═══════════════════════════════════════════════════════════════
#  PARALLEL ENGINE
# ═══════════════════════════════════════════════════════════════
def get_fast_account(region="BD", name_prefix="ARIYAN", password_prefix="ARIYAN"):
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(create_account, region, name_prefix, password_prefix) for _ in range(5)]
        for f in as_completed(futures):
            try:
                r = f.result()
                if r and r.get("account_id", "N/A") != "N/A":
                    return r
            except Exception:
                pass
    return create_account(region, name_prefix, password_prefix)

# ═══════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route('/gen', methods=['GET'])
def gen_multiple():
    name = request.args.get('name', 'ARIYAN')
    region = request.args.get('region', 'BD').upper()
    password_prefix = request.args.get('password_prefix', 'ARIYAN')
    try:
        count = int(request.args.get('count', '1'))
        count = max(1, min(count, 20))
    except Exception:
        count = 1

    if region not in REGION_LANG:
        region = "BD"

    results = []
    workers = max(5, count * 2)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(create_account, region, name, password_prefix) for _ in range(workers)]
        for f in as_completed(futures):
            try:
                r = f.result()
                if r and r.get("account_id", "N/A") != "N/A":
                    results.append(r)
                    if len(results) >= count:
                        break
            except Exception:
                pass

    return jsonify({
        "success": True,
        "total_requested": count,
        "total_created": len(results),
        "region": region,
        "accounts": results,
        "message": f"Created {len(results)} accounts in {region}",
    })

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET'])
def home(path):
    name = request.args.get('name', 'ARIYAN')
    region = request.args.get('region', 'BD').upper()
    password_prefix = request.args.get('password_prefix', 'ARIYAN')
    if region not in REGION_LANG:
        region = "BD"

    acc = get_fast_account(region, name, password_prefix)
    if acc and acc.get("account_id", "N/A") != "N/A":
        return jsonify({"status": "success", "account": acc})
    return jsonify({"status": "error", "message": "Server busy, please retry."}), 503

@app.route('/regions')
def regions():
    return jsonify({"regions": REGION_LANG, "available": list(REGION_LANG.keys())})

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "release": RELEASE_VERSION,
        "client_version": CLIENT_VERSION,
        "region_default": "BD",
    })

def application(environ, start_response):
    return app(environ, start_response)

if __name__ == '__main__':
    print(f"🚀 ARIYAN OB55 API running on port 8080...")
    app.run(host='0.0.0.0', port=8080, debug=False)
