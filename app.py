# ═══════════════════════════════════════════════════════════════
#  ARIYAN — BANGLADESH AUTO REGISTER (FLASK / VERCEL API)
# ═══════════════════════════════════════════════════════════════

import hmac, hashlib, requests, string, random, json, base64, re, uuid, time
from datetime import datetime
from flask import Flask, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
urllib3.disable_warnings()

app = Flask(__name__)

# ─────────── FIXED BD CONFIG ───────────
REGION = "BD"
LANG   = "bn"
PREFIX = "Aʀɪʏᴀɴ"

API_BASE   = "https://100067.connect.garena.com"
MAJOR_BASE = "https://loginbp.ppmainecoonghj.com"
API_HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

MAX_RETRY = 8   # Vercel-এর টাইট লিমিটের কারণে ৮ রাখা হলো

REG_HEADERS = {
    "Connection": "Keep-Alive",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json; charset=utf-8",
    "Host": "100067.connect.garena.com",
}

MAJOR_HEADERS = {
    "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "Accept-Encoding": "deflate, gzip",
    "X-GA-SV": "1789535859",
    "Authorization": "Bearer",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB55",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Unity-Version": "2018.4.12f1",
}

COOKIES = [
    "datadome=y23Z3X17pgkMHEt5zY8dqxC6BIf7WJMgC0RXNbqifHT7t9zajKe_hegFb1Ie9_7JixXpz7FRGVodOn~mWPk_NrqIIhUOXDYqKOahzoRQcyEy77GWEMcdA9_MqPJeM5qv",
    "datadome=oYpIhVco_RFvLHe_T9KFd5wuY0gcQuNfrlt4rHJY5QOkwv4TGt8gPMK32MbHuBdzJyfXnXlfzNZT_2tHr2kys8AMYT2~T71QP1S78_7Pdx4JLOXdSrflPT6cOX2vsyJh",
    "datadome=xJ8LmPnQvRtYbKc2dWfGhS4eZa9iUjM3oXpN6qT1vR7yL5kC8mB0nD4fH2gE6aJ",
]

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

KEYSTREAM = bytes([
    0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
    0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30
])

def sign(payload):
    return hmac.new(API_HEX_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()

def aes_enc(plain_hex):
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(bytes.fromhex(plain_hex), AES.block_size)).hex()

def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def field(fn, v):
    if isinstance(v, int):
        return varint((fn << 3)) + varint(v)
    ev = v.encode() if isinstance(v, str) else v
    return varint((fn << 3) | 2) + varint(len(ev)) + ev

def proto(d):
    return b''.join(field(k, v) for k, v in d.items())

def field14(open_id):
    ob = open_id.encode()
    return bytes([ob[i] ^ KEYSTREAM[i % 32] for i in range(len(ob))])

SUPERSCRIPT_DIGITS = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}

def to_superscript(s):
    return ''.join(SUPERSCRIPT_DIGITS.get(c, c) for c in s)

def rand_name():
    digits = ''.join(random.choice(string.digits) for _ in range(6))
    return PREFIX + to_superscript(digits)

def rand_pass():
    return "ARIYAN_BD_" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

def rand_dev():
    return {
        "device": random.choice(["SM-S918B","SM-S908B","SM-S928B","OnePlus 11","Xiaomi 13 Pro","Pixel 7 Pro"]),
        "carrier": random.choice(["Robi","Grameenphone","Banglalink","Airtel","Jio"]),
        "android": random.choice(["11","12","13","14"]),
    }

def ua_of(d):
    return f"GarenaMSDK/4.0.44({d['device']} ;Android {d['android']};{LANG};IND;app 2.127.1 2019118047;)"

def register_once():
    s = requests.Session(); s.verify = False
    password = rand_pass()
    name = rand_name()
    dev = rand_dev()
    ua = ua_of(dev)

    try:
        body = '{"app_id":100067,"client_type":2,"password":"%s","source":2}' % password
        h = dict(REG_HEADERS); h["User-Agent"]=ua; h["Cookie"]=random.choice(COOKIES)
        h["Authorization"] = f"Signature {sign(body)}"
        
        r = s.post(f"{API_BASE}/api/v2/oauth/guest:register", headers=h, data=body, timeout=15, verify=False)
        if r.status_code == 429: return {"ok": False, "error": "429", "retry": True}
        if r.status_code != 200: return {"ok": False, "error": f"Guest HTTP {r.status_code}"}

        j = r.json()
        if j.get("code") != 0: return {"ok": False, "error": f"Guest code {j.get('code')}", "retry": True}
        uid = j["data"]["uid"]

        hx = lambda n: ''.join(random.choice('0123456789abcdef') for _ in range(n))
        devid = f"02-{hx(8)}-{hx(4)}-{hx(4)}-{hx(4)}-{hx(12)}"
        body = ('{"client_id":100067,"client_secret":"%s","client_type":2,'
                '"device_id":"%s","password":"%s","response_type":"token","uid":%s}'
                ) % (API_HEX_KEY, devid, password, uid)
        h["Authorization"] = f"Signature {sign(body)}"
        h["Cookie"] = random.choice(COOKIES)
        
        r = s.post(f"{API_BASE}/api/v2/oauth/guest/token:grant", headers=h, data=body, timeout=15, verify=False)
        if r.status_code == 429: return {"ok": False, "error": "429", "retry": True}
        if r.status_code != 200: return {"ok": False, "error": f"Token HTTP {r.status_code}", "retry": True}

        j = r.json()
        if j.get("code") != 0: return {"ok": False, "error": f"Token code {j.get('code')}", "retry": True}
        at = j["data"]["access_token"]
        oid = j["data"]["open_id"]

        p = proto({
            1: name, 2: at, 3: oid, 5: 102000007, 6: 4, 7: 1, 13: 1,
            14: field14(oid), 15: LANG, 16: 1, 22: FIELD_22,
        })
        mh = dict(MAJOR_HEADERS); mh["Host"]="loginbp.ppmainecoonghj.com"
        mh["User-Agent"]=ua; mh["Content-Type"]="application/octet-stream"
        mh["Authorization"]=f"Bearer {at}"
        
        r = s.post(f"{MAJOR_BASE}/MajorRegister", headers=mh, data=bytes.fromhex(aes_enc(p.hex())), timeout=15, verify=False)
        if r.status_code == 429: return {"ok": False, "error": "429", "retry": True}
        if r.status_code != 200: return {"ok": False, "error": f"Register HTTP {r.status_code}", "retry": True}

        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        av = dev['android']; api = 30 + int(av) - 11
        lp = proto({
            3: ts, 4: "free fire", 5: 4, 7: "1.132.1", 8: "2019116753",
            9: f"Android OS {av} / API-{api} (SP1A.210812.016.C2)",
            10: "Handheld", 11: dev['device'], 12: 1280, 13: 720, 14: "240",
            15: "x86-64 SSE3 SSE4.1 SSE4.2 AVX AVX2 | 2400 | 4",
            16: random.choice([5951,6000,6100,5500,6500]),
            17: "Adreno 740", 18: "OpenGL ES 3.1 v1.46",
            19: f"Google|{uuid.uuid4()}",
            20: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            21: LANG, 22: oid, 23: "4", 24: "Handheld", 25: dev['device'],
            26: "IND", 29: at, 30: 1, 41: dev['carrier'], 42: "WIFI",
            92: random.choice([19788,20000,21000]),
            93: "android_max", 97: 1, 98: 1, 99: "4", 100: "4", 104: 77149, 105: 1,
        })
        
        r = s.post(f"{MAJOR_BASE}/MajorLogin", headers=mh, data=bytes.fromhex(aes_enc(lp.hex())), timeout=15, verify=False)
        if r.status_code == 429: return {"ok": False, "error": "429", "retry": True}
        if r.status_code != 200: return {"ok": False, "error": f"Login HTTP {r.status_code}", "retry": True}

        m = re.search(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", r.content)
        if not m: return {"ok": False, "error": "JWT missing", "retry": True}
        token = m.group(0).decode()

        acc = "N/A"; lvl = 1; nick = name
        try:
            pb = token.split('.')[1]; pad_ = '=' * (-len(pb) % 4)
            dj = json.loads(base64.urlsafe_b64decode(pb + pad_))
            acc = dj.get('account_id') or dj.get('external_id') or dj.get('uid') or "N/A"
            lvl = dj.get('level') or dj.get('lv') or 1
            nick = dj.get('nickname') or dj.get('name') or name
        except: pass

        return {
            "ok": True, "name": name, "nickname": str(nick), "uid": str(uid),
            "password": password, "account_id": str(acc), "level": int(lvl) if str(lvl).isdigit() else lvl,
            "region": "BD", "lang": LANG, "open_id": oid, "token": token,
            "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:100]}", "retry": True}
    finally:
        try: s.close()
        except: pass

def register():
    last_err = "unknown"
    for attempt in range(1, MAX_RETRY + 1):
        r = register_once()
        if r.get("ok"):
            r["attempts"] = attempt
            return r
        last_err = r.get("error", "unknown")
        if "429" in last_err: time.sleep(1.5)
        else: time.sleep(0.5)
    return {"ok": False, "error": f"{MAX_RETRY} বার চেষ্টার পরও ব্যর্থ ({last_err})"}

# Flask Route
@app.route('/')
def index():
    result = register()
    if result.get("ok"):
        payload = {
            "status": "SUCCESS", "attempts": result.get("attempts", 1),
            "name": result.get("name"), "nickname": result.get("nickname"),
            "uid": result.get("uid"), "password": result.get("password"),
            "account_id": result.get("account_id"), "level": result.get("level"),
            "region": result.get("region"), "lang": result.get("lang"),
            "open_id": result.get("open_id"), "token": result.get("token"),
            "time": result.get("time"),
        }
        return jsonify(payload), 200
    else:
        payload = {
            "status": "FAILED", "error": result.get("error", "unknown"),
            "attempts": MAX_RETRY, "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        return jsonify(payload), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
