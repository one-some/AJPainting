import os
import sys
import uuid
import zlib
import requests
from Crypto.Cipher import AES

s = requests.session()

def get_json(url, params = None, headers = None):
    headers = headers or {}

    if params:
        url += "?" + ("&".join(params))
    r = s.get(url, headers=headers)

    if r.status_code != 200:
        print(r.status_code)
        assert False

    return r.json()

def post_json(url, data = None):
    r = s.post(url, json=data)

    if r.status_code != 200:
        print(r.status_code)
        assert False

    return r.json()

def get_uuid(username: str, password: str) -> str:
    flash_vars = get_json("https://animaljam.com/flashvars")
    random_uuid = str(uuid.uuid4())

    auth_data = post_json(
        "https://authenticator.animaljam.com/authenticate",
        {"username": username, "password": password, "domain": "flash", "df": random_uuid},
    )

    auth_token = auth_data["auth_token"]
    client_version = flash_vars["deploy_version"]
    session_data = get_json(
        "https://player-session-data.animaljam.com/player",
        ["domain=flash", f"client_version={client_version}"],
        {"Authorization": f"Bearer {auth_token}"}
    )
    return session_data["uuid"]

def get_secrets(uuid: str):
    key = ""
    iv = ""

    index = 0
    while len(key) < 16:
        key += uuid[index]
        index += 1
        iv  += uuid[index]
        index += 1

    return key.encode("utf-8"), iv.encode("utf-8")

def encode_u29(n: int) -> bytes:
    # u29 is a variable length format
    if n < 0x80:
            return bytes([n])
    elif n < 0x3fff:
        return bytes([((n >> 7) & 0x7F) | 0x80, (n & 0x7F)])
    elif n < 0x200000:
        return bytes([
            ((n >> 14) & 0x7F) | 0x80, 
            ((n >> 7) & 0x7F) | 0x80, 
            (n & 0x7F)
        ])
    elif n < 0x40000000:
        return bytes([
            ((n >> 22) & 0x7F) | 0x80,
            ((n >> 15) & 0x7F) | 0x80,
            ((n >> 8) & 0x7F) | 0x80,
            (n & 0xFF)
        ])
    assert False

def pad_zeros(data: bytes) -> bytes:
    block_size = 16
    remainder = len(data) % block_size
    if remainder == 0:
        return data
    padding_needed = block_size - remainder
    return data + (b'\x00' * padding_needed)

def overwrite_or_die(path) -> bool:
    while os.path.exists(path):
        print(f"[WARNING!!] {out_path} exists... Overwrite it?")
        choice = input("y/n: ")

        if choice == "n":
            print("OK, quitting doing nothing.")
            exit(0)
        elif choice == "y":
            print("OK, overwriting")
            return
        
        print("Didn't understand! Choose y or n.")

def decrypt(raw: bytes, key: bytes, iv: bytes, out_path: str) -> None:
    cipher = AES.new(key, AES.MODE_CBC, iv)

    compressed = cipher.decrypt(raw)
    amf = zlib.decompress(compressed)

    start_png = amf.find(b"\x89PNG")
    end_png = amf.find(b"\x00\x00\x00\x00IEND\xaeB\x60\x82") + (4 * 3)
    png = amf[start_png:end_png]

    overwrite_or_die(out_path)
    with open(out_path, "wb") as file:
        file.write(png)

def encrypt(raw: bytes, key: bytes, iv: bytes, out_path: str) -> None:
    amf = b'\x0A\x0B\x01'
    amf += b'\x03b' # "b"
    amf += b'\x0C' # ByteArray

    amf_len = (len(raw) << 1) | 1
    amf += encode_u29(amf_len)
    amf += raw

    amf += b'\x03h' # "h"
    amf += b'\x06' # String
    amf += b'\x0D' # Strlen
    amf += "aja2id".encode('utf-8')

    amf += b'\x03p' # "p"
    amf += b'\x06' # String
    amf += b'\x49' # Strlen
    amf += uuid.encode('utf-8')

    amf += b'\x01' # EOO ^_^

    compressed = zlib.compress(amf, level=9)

    padded = pad_zeros(compressed)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded)

    overwrite_or_die(out_path)
    with open(out_path, "wb") as file:
        file.write(encrypted_data)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Please run like this: python painting.py [username:password] [target filename]")
        exit(1)

    _, credentials, target = sys.argv

    ext = target.rsplit(".")[-1]
    assert ext in ["png", "ajart"]

    username, password = credentials.split(":", 1)
    uuid = get_uuid(username, password)
    key, iv = get_secrets(uuid)

    with open(target, "rb") as file:
        data = file.read()

    out_path = out_path = target.rsplit(".", 1)[0] + (".png" if ext == "ajart" else ".ajart")
    if ext == "ajart":
        decrypt(data, key, iv, out_path)
    elif ext == "png":
        encrypt(data, key, iv, out_path)

    print("Done! Find your file at", out_path)
