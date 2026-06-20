#!/usr/bin/env python3
"""source.html をパスワードで AES-256-GCM 暗号化し、パスワードゲート付き index.html を生成する。
使い方:  python3 build.py 'パスワード'
平文(source.html)は push しない（.gitignore 済み）。生成された index.html は暗号文のみを含む。"""
import os, sys, json, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if len(sys.argv) < 2:
    print("usage: python3 build.py 'password'"); sys.exit(1)
pw = sys.argv[1].encode()
plaintext = open("source.html", "rb").read()

ITER = 250000
salt = os.urandom(16)
iv = os.urandom(12)
kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=ITER)
key = kdf.derive(pw)
ct = AESGCM(key).encrypt(iv, plaintext, None)  # tag は ct 末尾に付与

enc = {
    "salt": base64.b64encode(salt).decode(),
    "iv": base64.b64encode(iv).decode(),
    "ct": base64.b64encode(ct).decode(),
    "iter": ITER,
}

gate = '''<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="googlebot" content="noindex, nofollow">
<title>合同会社440 — 社内資料</title>
<style>
  :root{--paper:#f6f4ee;--ink:#1b1e1a;--ink-soft:#52584d;--line:#c7c0ae;--accent:#0e6b54;--amber:#9a5b12}
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{background:var(--paper);color:var(--ink);font-family:"Hiragino Sans","Noto Sans JP",system-ui,sans-serif;
    display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
  .gate{width:100%;max-width:380px;text-align:center}
  .mark{font-family:"Hiragino Mincho ProN","Noto Serif JP",serif;font-size:13px;letter-spacing:.3em;color:var(--accent);font-weight:700;margin-bottom:10px}
  h1{font-family:"Hiragino Mincho ProN","Noto Serif JP",serif;font-weight:600;font-size:20px;margin-bottom:6px;letter-spacing:.02em}
  p.lead{font-size:12.5px;color:var(--ink-soft);margin-bottom:24px;line-height:1.6}
  .field{display:flex;gap:8px}
  input{flex:1;padding:11px 13px;border:1px solid var(--line);border-radius:7px;background:#fffefb;font-size:15px;font-family:inherit;color:var(--ink)}
  input:focus{outline:none;border-color:var(--accent)}
  button{padding:11px 18px;border:none;border-radius:7px;background:var(--accent);color:#fff;font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;white-space:nowrap}
  button:hover{background:#0a553f}
  button:disabled{opacity:.5;cursor:default}
  .msg{margin-top:14px;font-size:12.5px;min-height:18px;color:var(--amber);font-weight:600}
  .foot{margin-top:28px;font-size:10.5px;color:var(--ink-soft);letter-spacing:.04em}
</style>
</head>
<body>
  <div class="gate">
    <div class="mark">440</div>
    <h1>社内資料</h1>
    <p class="lead">この資料はパスワードで保護されています。<br>パスワードを入力してください。</p>
    <form id="f" class="field" autocomplete="off">
      <input id="pw" type="password" placeholder="パスワード" autofocus aria-label="パスワード">
      <button id="b" type="submit">解錠</button>
    </form>
    <div class="msg" id="m"></div>
    <div class="foot">合同会社440 — 関係者外秘</div>
  </div>
<script>
const ENC = __ENC__;
const f=document.getElementById('f'),pw=document.getElementById('pw'),b=document.getElementById('b'),m=document.getElementById('m');
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function unlock(pass){
  const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(ENC.salt),iterations:ENC.iter,hash:'SHA-256'},
    km,{name:'AES-GCM',length:256},false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(ENC.iv)},key,b64(ENC.ct));
  return new TextDecoder().decode(pt);
}
f.addEventListener('submit',async e=>{
  e.preventDefault();
  if(!pw.value)return;
  b.disabled=true;m.textContent='確認中…';m.style.color='var(--ink-soft)';
  try{
    const html=await unlock(pw.value);
    document.open();document.write(html);document.close();
  }catch(err){
    m.textContent='パスワードが違います';m.style.color='var(--amber)';
    b.disabled=false;pw.value='';pw.focus();
  }
});
</script>
</body>
</html>'''

gate = gate.replace("__ENC__", json.dumps(enc))
open("index.html", "w", encoding="utf-8").write(gate)
print("built index.html (encrypted) — plaintext stays in source.html (gitignored)")
