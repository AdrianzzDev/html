#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import secrets
import string
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("anu nya belum terpasang.")
    print("commnd: pkg install python-cryptography")
    sys.exit(1)


OUTPUT_DIR = Path(os.environ.get("VALEZ_OUT", "/sdcard/A_ENCRIPSI_HTML"))
AAD = b"VALEZ-HTML-v1"
PBKDF2_ROUNDS = 120_000


def to_b64(value):
    return base64.b64encode(value).decode("ascii")


def input_html():
    while True:
        raw = input("path html bro: ").strip()

        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
            raw = raw[1:-1].strip()

        if not raw:
            print("path kosong, coba lagi.")
            continue

        path = Path(raw).expanduser()

        if not path.is_file():
            print("file tidak ditemukan")
            continue

        if path.suffix.lower() not in (".html", ".htm"):
            print("file harus berakhiran .html atao .htm")
            continue

        try:
            content = path.read_bytes()
        except OSError as exc:
            print(f"gagal membaca file: {exc}")
            continue

        destination = OUTPUT_DIR / path.name

        try:
            same = path.resolve() == destination.resolve()
        except OSError:
            same = False

        if same:
            print("pilih file sumber di luar folder output.")
            continue

        return path, content


def random_identifier(used):
    alphabet = string.ascii_letters

    while True:
        name = "_" + "".join(secrets.choice(alphabet) for _ in range(14))
        if name not in used:
            used.add(name)
            return name


def scramble_string(value, chunk_size):
    chunks = [value[i:i + chunk_size] for i in range(0, len(value), chunk_size)]
    shuffled_indices = list(range(len(chunks)))
    secrets.SystemRandom().shuffle(shuffled_indices)
    shuffled = [chunks[i] for i in shuffled_indices]

    order = [0] * len(chunks)
    for shuffled_position, original_position in enumerate(shuffled_indices):
        order[original_position] = shuffled_position

    return shuffled, order


def js_json(value):
    return json.dumps(value, separators=(",", ":"))


def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ROUNDS,
    )
    return kdf.derive(passphrase)


JS_TEMPLATE = r"""(async()=>{
"use strict";
const @@V01@@=@@PAYLOAD_PARTS@@,@@V02@@=@@PAYLOAD_ORDER@@;
const @@V03@@=@@PASS_PARTS@@,@@V04@@=@@PASS_ORDER@@;
const @@V05@@=@@SALT_PARTS@@,@@V06@@=@@SALT_ORDER@@;
const @@V07@@=@@IV_PARTS@@,@@V08@@=@@IV_ORDER@@;
const @@V09@@=a=>Uint8Array.from(atob(a),c=>c.charCodeAt(0));
const @@V10@@=(p,o)=>o.map(i=>p[i]).join("");
const @@V11@@=m=>{
  document.title="Gagal Memuat";
  const c=document.querySelector("main");
  if(c)c.innerHTML='<h2 style="margin:0 0 10px;color:#ff5c8a;font-size:15px;letter-spacing:2px">X-VALEZ</h2><p style="margin:0;color:#bba9ca;font-size:13px;line-height:1.6">'+m+'</p>';
};
let ok=false;
const timer=setTimeout(()=>{if(!ok)@@V11@@("Waktu habis. Browser lambat atau Web Crypto tidak didukung.");},20000);
try{
  const enc=new TextEncoder();
  const aes=atob("QUVTLUdDTQ==");
  const pbk=atob("UEJLREYy");
  const raw=await crypto.subtle.importKey("raw",@@V09@@(@@V10@@(@@V03@@,@@V04@@)),pbk,false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:pbk,salt:@@V09@@(@@V10@@(@@V05@@,@@V06@@)),iterations:120000,hash:"SHA-256"},raw,{name:aes,length:256},false,["decrypt"]);
  const pt=await crypto.subtle.decrypt({name:aes,iv:@@V09@@(@@V10@@(@@V07@@,@@V08@@)),additionalData:enc.encode(atob("VkFMRVotSFRNTC12MQ=="))},key,@@V09@@(@@V10@@(@@V01@@,@@V02@@)));
  ok=true;clearTimeout(timer);
  const html=new TextDecoder().decode(pt);
  const parsed=new DOMParser().parseFromString(html,"text/html");
  document.documentElement.replaceWith(document.adoptNode(parsed.documentElement));
  [...document.querySelectorAll("script")].forEach(old=>{
    const s=document.createElement("script");
    for(const a of old.attributes)s.setAttribute(a.name,a.value);
    s.textContent=old.textContent;
    old.replaceWith(s);
  });
}catch(e){
  clearTimeout(timer);
  @@V11@@("Gagal membuka halaman. File rusak, sudah diubah, atau Web Crypto tidak didukung.");
}
})();
"""


def make_html(ciphertext, passphrase, salt, nonce):
    payload_parts, payload_order = scramble_string(to_b64(ciphertext), 48)
    pass_parts, pass_order = scramble_string(to_b64(passphrase), 6)
    salt_parts, salt_order = scramble_string(to_b64(salt), 4)
    iv_parts, iv_order = scramble_string(to_b64(nonce), 4)

    used = set()
    names = {f"@@V{i:02d}@@": random_identifier(used) for i in range(1, 12)}

    script = JS_TEMPLATE
    values = {
        "@@PAYLOAD_PARTS@@": js_json(payload_parts),
        "@@PAYLOAD_ORDER@@": js_json(payload_order),
        "@@PASS_PARTS@@": js_json(pass_parts),
        "@@PASS_ORDER@@": js_json(pass_order),
        "@@SALT_PARTS@@": js_json(salt_parts),
        "@@SALT_ORDER@@": js_json(salt_order),
        "@@IV_PARTS@@": js_json(iv_parts),
        "@@IV_ORDER@@": js_json(iv_order),
    }

    for token, value in values.items():
        script = script.replace(token, value)
    for token, name in names.items():
        script = script.replace(token, name)

    return """<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Memuat…</title>
<style>
*{box-sizing:border-box}
body{
  margin:0;
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:22px;
  color:#f4e9ff;
  background:radial-gradient(ellipse at top,#321052,transparent 60%),#08040f;
  font-family:system-ui,-apple-system,sans-serif
}
main{
  width:100%;
  max-width:390px;
  padding:30px 26px;
  text-align:center;
  background:linear-gradient(145deg,#1b0b2c,#0d0616);
  border:1px solid #9d4edd;
  border-radius:22px;
  box-shadow:0 0 34px #9d4edd40
}
.ring{
  width:36px;
  height:36px;
  margin:0 auto 18px;
  border-radius:50%;
  border:3px solid #9d4edd33;
  border-top-color:#c77dff;
  animation:spin .8s linear infinite
}
@keyframes spin{to{transform:rotate(1turn)}}
.status{display:block;color:#c77dff;font-size:13px;letter-spacing:4px}
.sub{margin:10px 0 0;color:#bba9ca;font-size:12.5px;line-height:1.6}
</style>
</head>
<body>
<main>
  <div class="ring"></div>
  <b class="status">MEMBUKA HALAMAN</b>
  <p class="sub">Memverifikasi integritas file…</p>
  <noscript><p class="sub">JavaScript diperlukan untuk membuka halaman ini.</p></noscript>
</main>
<script>
""" + script + """
</script>
</body>
</html>
"""


def main():
    source, content = input_html()

    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        passphrase = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = derive_key(passphrase, salt)

        ciphertext = AESGCM(key).encrypt(nonce, content, AAD)
        result = make_html(ciphertext, passphrase, salt, nonce)

        destination = OUTPUT_DIR / source.name
        destination.write_text(result, encoding="utf-8")
    except OSError as exc:
        print(f"gagal menyimpan: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"proses gagal: {exc}")
        sys.exit(1)

    print(f"\nberhasil: {destination}")
    print(f"ukuran: {len(content)} -> {len(result)} byte")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
