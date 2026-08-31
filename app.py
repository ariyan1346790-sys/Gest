from flask import Flask, request, jsonify
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
import re
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", 
    "TH": "th", "BD": "bn", "PK": "ur", "TW": "zh", 
    "CIS": "ru", "SAC": "es", "BR": "pt"
}

HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
_HIDDEN = "ZUYxTCP"
DEVICE_POOL = [
    {"model": "SM-G973F", "brand": "Samsung", "android": "12", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G973F Build/SP1A.210812.016)"},
    {"model": "SM-G998B", "brand": "Samsung", "android": "13", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 13; SM-G998B Build/TP1A.220624.014)"},
    {"model": "SM-G991B", "brand": "Samsung", "android": "13", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 13; SM-G991B Build/TP1A.220624.014)"},
    {"model": "M2101K7AG", "brand": "Xiaomi", "android": "12", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)"},
    {"model": "M2012K11AG", "brand": "Xiaomi", "android": "13", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 13; M2012K11AG Build/TKQ1.220829.002)"},
    {"model": "LE2121", "brand": "OnePlus", "android": "13", "user_agent": "Dalvik/2.1.0 (Linux; U; Android 13; LE2121 Build/TP1A.220905.001)"},
]
thread_local = threading.local()
def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        thread_local.session.verify = False
        thread_local.session.timeout = 10
        device = random.choice(DEVICE_POOL)
        thread_local.session.headers.update({
            'User-Agent': device['user_agent'],
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        })
    return thread_local.session
def encode_varint(n):
    if n < 0:
        return b''
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            byte |= 0x80
        result.append(byte)
        if not n:
            break
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

def aes_encrypt(hex_data):
    data = bytes.fromhex(hex_data)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()

def generate_exponent():
    exp_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    num = random.randint(1, 9999)
    return ''.join(exp_digits[d] for d in f"{num:04d}")

def generate_random_name(base):
    return f"{base}{generate_exponent()}"

def generate_custom_password(user_prefix):
    random_part = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(8))
    return f"{user_prefix}_{_HIDDEN}_{random_part}"
def create_account(region, account_name, password_prefix):
    session = get_session()
    for _ in range(3):
        try:
            password = generate_custom_password(password_prefix)
            url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
            payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }
            response = session.post(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            res_json = response.json()
            if "data" in res_json and "uid" in res_json["data"]:
                uid = res_json["data"]["uid"]
                return get_token(uid, password, region, account_name, password_prefix)
        except Exception as e:
            continue
    return None

def get_token(uid, password, region, account_name, password_prefix):
    session = get_session()
    for _ in range(3):
        try:
            url = "https://100067.connect.garena.com/oauth/guest/token/grant"
            headers = {
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "100067.connect.garena.com",
            }
            body = {
                "uid": uid,
                "password": password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": HEX_KEY,
                "client_id": "100067"
            }
            response = session.post(url, headers=headers, data=body, timeout=10)
            response.raise_for_status()
            data = response.json()
            if 'open_id' in data and 'access_token' in data:
                open_id = data['open_id']
                access_token = data["access_token"]
                
                # XOR encode open_id
                keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 
                            0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
                encoded = ""
                for i in range(len(open_id)):
                    encoded += chr(ord(open_id[i]) ^ keystream[i % len(keystream)])
                field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')
                
                return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix)
        except Exception as e:
            continue
    return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix):
    session = get_session()
    for _ in range(3):
        try:
            if region.upper() in ["ME", "TH"]:
                url = "https://loginbp.common.ggbluefox.com/MajorRegister"
            else:
                url = "https://loginbp.ggblueshark.com/MajorRegister"
            
            name = generate_random_name(account_name)
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "ReleaseVersion": "ob54",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4."
            }
            
            lang_code = REGION_LANG.get(region.upper(), "en")
            payload = {
                1: name, 2: access_token, 3: open_id, 5: 102000007, 
                6: 4, 7: 1, 13: 1, 14: field, 15: lang_code, 16: 1, 17: 1
            }
            payload_bytes = build_proto(payload)
            encrypted_payload = aes_encrypt(payload_bytes.hex())
            response = session.post(url, headers=headers, data=encrypted_payload, timeout=10)
            
            login_result = major_login(uid, password, access_token, open_id, region)
            account_id = login_result.get("account_id", "N/A")
            jwt_token = login_result.get("jwt_token", "")
            
            if account_id != "N/A":
                return {
                    "uid": uid,
                    "password": password,
                    "name": name,
                    "region": region,
                    "status": "success",
                    "account_id": account_id,
                    "jwt_token": jwt_token
                }
        except Exception as e:
            continue
    return None

def major_login(uid, password, access_token, open_id, region):
    try:
        lang = REGION_LANG.get(region.upper(), "en")
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        payload = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        payload = payload.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        
        if region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        else:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
            
        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "ReleaseVersion": "ob54",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1"
        }
        
        encrypted = encrypt_api(payload.hex())
        session = get_session()
        response = session.post(url, headers=headers, data=bytes.fromhex(encrypted), timeout=10)
        
        if response.status_code == 200 and len(response.text) > 10:
            jwt_start = response.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = response.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            payload_part = parts[1]
                            padding = 4 - len(payload_part) % 4
                            if padding != 4:
                                payload_part += '=' * padding
                            decoded = base64.urlsafe_b64decode(payload_part)
                            data = json.loads(decoded)
                            account_id = data.get('account_id') or data.get('external_id')
                            if account_id:
                                return {"account_id": str(account_id), "jwt_token": jwt_token}
                    except:
                        pass
        return {"account_id": "N/A", "jwt_token": ""}
    except Exception as e:
        return {"account_id": "N/A", "jwt_token": ""}

@app.route('/gen', methods=['GET'])
def generate_accounts():
    name = request.args.get('name', 'HUSTLER')
    count = request.args.get('count', '1')
    region = request.args.get('region', 'IND')
    password_prefix = request.args.get('password_prefix', 'FF')
    try:
        count = int(count)
        if count > 20:
            count = 20
        if count < 1:
            count = 1
    except:
        count = 1
    region = region.upper()
    if region not in REGION_LANG:
        region = "IND"
    
    print(f"[API] Generating {count} accounts for region {region} with name {name}")
    
    results = []
    attempts = 0
    max_attempts = count * 5
    
    while len(results) < count and attempts < max_attempts:
        attempts += 1

        account_data = create_account(region, name, password_prefix)
        
        if account_data and account_data.get('account_id', 'N/A') != 'N/A':
            results.append(account_data)
            print(f"[API] Created account {len(results)}/{count}: {account_data.get('account_id')}")
    
        time.sleep(0.5)
    
    response_data = {
        "success": True,
        "total_requested": count,
        "total_created": len(results),
        "attempts_made": attempts,
        "accounts": results,
        "region": region,
        "message": f"Created {len(results)} accounts in {region} region"
    }
    
    return jsonify(response_data)

from flask import Response

@app.route('/')
def home():
    return Response(status=204)

@app.route('/regions')
def regions():
    return jsonify({
        "regions": REGION_LANG,
        "available": list(REGION_LANG.keys())
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "message": "API is running", "version": "2.0"})

# ========== WSGI ENTRY POINT ==========
def application(environ, start_response):
    return app(environ, start_response)
if __name__ == '__main__':
    print("Script Running")
    app.run(host='0.0.0.0', port=8080, debug=False)