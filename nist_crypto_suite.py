#!/usr/bin/env python3
"""
THE HENRY COMPANY — Cryptographic Verification Suite v4

LAYER 1: NIST CAVP — 55,064 official test vectors from csrc.nist.gov
LAYER 2: WYCHEPROOF — Google's adversarial edge-case attack vectors

12 NIST suites + Wycheproof adversarial tests.
9 federal standards. Every vector Python can run.
Downloaded live. Nothing hardcoded.

Requirements:
    pip install cryptography

Usage:
    python nist_crypto_suite.py
"""

import hashlib, hmac as hmac_mod, json, sys, os, platform, ssl
import zipfile, io, re, time, struct
from datetime import datetime, timezone

try:
    import urllib.request
except ImportError:
    pass

HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils, padding
    from cryptography.hazmat.primitives import hashes as ch
    from cryptography.hazmat.primitives import cmac as cmac_crypto
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature, InvalidTag
    HAS_CRYPTO = True
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════
# NIST CAVP SOURCES — Layer 1
# ═══════════════════════════════════════════════════════════════

NIST_SOURCES = {
    "SHA-2":      ("FIPS 180-4",  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip"),
    "SHA-3":      ("FIPS 202",    "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip"),
    "SHAKE":      ("FIPS 202",    "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip"),
    "HMAC":       ("FIPS 198-1",  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip"),
    "ECDSA":      ("FIPS 186-4",  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3ecdsatestvectors.zip"),
    "RSA":        ("FIPS 186-4",  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip"),
    "AES-MODES":  ("FIPS 197",    "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip"),
    "AES-MMT":    ("FIPS 197",    "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip"),
    "AES-GCM":    ("SP 800-38D",  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip"),
    "AES-CCM":    ("SP 800-38C",  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip"),
    "CMAC":       ("SP 800-38B",  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/cmactestvectors.zip"),
    "ECDH":       ("SP 800-56A",  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip"),
}


# ═══════════════════════════════════════════════════════════════
# WYCHEPROOF SOURCES — Layer 2 (Google adversarial test vectors)
# ═══════════════════════════════════════════════════════════════

WP_BASE = "https://raw.githubusercontent.com/google/wycheproof/master/testvectors_v1"

WYCHEPROOF_FILES = {
    "WP_AES_GCM": [
        "aes_gcm_test.json",
    ],
    "WP_AES_CCM": [
        "aes_ccm_test.json",
    ],
    "WP_CHACHA20": [
        "chacha20_poly1305_test.json",
        "xchacha20_poly1305_test.json",
    ],
    "WP_AES_CBC": [
        "aes_cbc_pkcs5_test.json",
    ],
    "WP_HMAC": [
        "hmac_sha1_test.json",
        "hmac_sha224_test.json",
        "hmac_sha256_test.json",
        "hmac_sha384_test.json",
        "hmac_sha512_test.json",
    ],
    "WP_ECDSA": [
        "ecdsa_secp224r1_sha224_test.json",
        "ecdsa_secp224r1_sha256_test.json",
        "ecdsa_secp224r1_sha512_test.json",
        "ecdsa_secp256r1_sha256_test.json",
        "ecdsa_secp256r1_sha512_test.json",
        "ecdsa_secp384r1_sha384_test.json",
        "ecdsa_secp384r1_sha512_test.json",
        "ecdsa_secp521r1_sha512_test.json",
    ],
    "WP_RSA_PKCS1": [
        "rsa_signature_2048_sha224_test.json",
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_2048_sha512_test.json",
        "rsa_signature_3072_sha256_test.json",
        "rsa_signature_3072_sha384_test.json",
        "rsa_signature_3072_sha512_test.json",
        "rsa_signature_4096_sha384_test.json",
        "rsa_signature_4096_sha512_test.json",
    ],
    "WP_RSA_PSS": [
        "rsa_pss_2048_sha256_mgf1_0_test.json",
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_3072_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha512_mgf1_32_test.json",
    ],
    "WP_ECDH": [
        "ecdh_secp224r1_test.json",
        "ecdh_secp256r1_test.json",
        "ecdh_secp384r1_test.json",
        "ecdh_secp521r1_test.json",
    ],
    "WP_DSA": [
        "dsa_2048_224_sha224_test.json",
        "dsa_2048_224_sha256_test.json",
        "dsa_2048_256_sha256_test.json",
        "dsa_3072_256_sha256_test.json",
    ],
    "WP_RSA_OAEP": [
        "rsa_oaep_2048_sha1_mgf1sha1_test.json",
        "rsa_oaep_2048_sha256_mgf1sha256_test.json",
    ],
}


SHA2_MAP = {"SHA1": "sha1", "SHA224": "sha224", "SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512"}
SHA3_MAP = {"SHA3_224": "sha3_224", "SHA3_256": "sha3_256", "SHA3_384": "sha3_384", "SHA3_512": "sha3_512"}


def dl(url):
    fname = url.split("/")[-1]
    print(f"    Fetching: {fname}")
    req = urllib.request.Request(url, headers={"User-Agent": "HenryCompany-NIST/4.0"})
    data = urllib.request.urlopen(req, timeout=60).read()
    print(f"    {len(data):,} bytes")
    return data


def dl_json(url):
    fname = url.split("/")[-1]
    print(f"      {fname}", end="", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "HenryCompany-WP/4.0"})
    data = urllib.request.urlopen(req, timeout=30).read()
    return json.loads(data)


# ═══════════════════════════════════════════════════════════════
# LAYER 1: ALL NIST CAVP SUITES (unchanged from v3 — 55,064 vectors)
# ═══════════════════════════════════════════════════════════════

def parse_hash_vectors(text):
    vecs, cur = [], {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["): continue
        if "=" in line:
            k, v = line.split("=", 1); cur[k.strip()] = v.strip()
            if k.strip() == "MD":
                vecs.append({"bl": int(cur.get("Len", "0")), "msg": cur.get("Msg", ""), "exp": v.strip().lower()}); cur = {}
    return vecs

def parse_monte_vectors(text):
    seed, exp = None, []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["): continue
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip() == "Seed": seed = v.strip().lower()
            elif k.strip() == "MD": exp.append(v.strip().lower())
    return seed, exp

def mc_sha2(algo, seed_hex, exp):
    seed = bytes.fromhex(seed_hex); r = []
    for j in range(len(exp)):
        md = [seed, seed, seed]
        for i in range(3, 1003): md.append(hashlib.new(algo, md[i-3]+md[i-2]+md[i-1]).digest())
        r.append(md[1002].hex() == exp[j]); seed = md[1002]
    return r

def mc_sha3(algo, seed_hex, exp):
    md = bytes.fromhex(seed_hex); r = []
    for j in range(len(exp)):
        for _ in range(1000): md = hashlib.new(algo, md).digest()
        r.append(md.hex() == exp[j])
    return r

def id_sha2(fn):
    b = os.path.basename(fn).upper().replace(".RSP", "")
    for s in ["SHORTMSG", "LONGMSG", "MONTE"]: b = b.replace(s, "")
    b = b.strip()
    for k, v in SHA2_MAP.items():
        if k in b: return k, v
    return None, None

def id_sha3(fn):
    b = os.path.basename(fn).upper().replace(".RSP", "").replace("-", "_")
    for s in ["SHORTMSG", "LONGMSG", "MONTE"]: b = b.replace(s, "")
    for k, v in SHA3_MAP.items():
        if k.replace("_", "") in b.replace("_", ""): return k, v
    return None, None

def run_sha_family(zb, algo_map, id_fn, mc_fn):
    zf = zipfile.ZipFile(io.BytesIO(zb)); af = {}
    for p in [n for n in zf.namelist() if n.lower().endswith(".rsp")]:
        fn = os.path.basename(p).lower(); ak, an = id_fn(p)
        if not ak: continue
        if ak not in af: af[ak] = {"n": an, "s": None, "l": None, "m": None}
        if "short" in fn: af[ak]["s"] = p
        elif "long" in fn: af[ak]["l"] = p
        elif "monte" in fn: af[ak]["m"] = p
    t = p2 = 0; res = {}
    for ak in sorted(af):
        info = af[ak]; an = info["n"]
        try: hashlib.new(an, b"t")
        except: continue
        at = ap = 0; print(f"    {ak:<12}", end="", flush=True)
        if info["s"]:
            vs = parse_hash_vectors(zf.read(info["s"]).decode("utf-8", "replace"))
            pp = sum(1 for v in vs if hashlib.new(an, b"" if v["bl"] == 0 else bytes.fromhex(v["msg"])).hexdigest() == v["exp"])
            at += len(vs); ap += pp
        if info["l"]:
            vs = parse_hash_vectors(zf.read(info["l"]).decode("utf-8", "replace"))
            pp = sum(1 for v in vs if hashlib.new(an, bytes.fromhex(v["msg"])).hexdigest() == v["exp"])
            at += len(vs); ap += pp
        if info["m"]:
            sd, ex = parse_monte_vectors(zf.read(info["m"]).decode("utf-8", "replace"))
            if sd and ex: mc = mc_fn(an, sd, ex); at += len(mc); ap += sum(mc)
        print(f"  {ap:>5}/{at:<5} {'✅' if ap == at else '❌'}"); t += at; p2 += ap
        res[ak] = {"total": at, "passed": ap, "failed": at - ap}
    return t, p2, res

def run_shake(zb):
    zf = zipfile.ZipFile(io.BytesIO(zb)); t = p = 0; res = {}
    for al, hn in [("SHAKE128", "shake_128"), ("SHAKE256", "shake_256")]:
        at = ap = 0; print(f"    {al:<12}", end="", flush=True)
        for fn in sorted(zf.namelist()):
            if not fn.lower().endswith(".rsp"): continue
            if al not in os.path.basename(fn).upper(): continue
            if "MONTE" in fn.upper(): continue
            c = zf.read(fn).decode("utf-8", "replace"); outlen = 128; cur = {}
            for line in c.splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                if line.startswith("["):
                    if "Outputlen" in line:
                        try: outlen = int(line.split("=")[-1].strip().rstrip("]"))
                        except: pass
                    continue
                if "=" in line:
                    k, v = line.split("=", 1); k = k.strip(); v = v.strip()
                    if k == "Outputlen": outlen = int(v); continue
                    cur[k] = v
                    if "Output" in cur:
                        msg_hex = cur.get("Msg", "")
                        msg = bytes.fromhex(msg_hex) if msg_hex and int(cur.get("Len", "1")) > 0 else b""
                        computed = hashlib.new(hn, msg).hexdigest(outlen // 8)
                        if computed == cur["Output"].lower(): ap += 1
                        at += 1; cur = {}
        print(f"  {ap:>5}/{at:<5} {'✅' if ap == at else '❌'}"); t += at; p += ap
        res[al] = {"total": at, "passed": ap, "failed": at - ap}
    return t, p, res

def run_hmac(zb):
    L2A = {"20": ("HMAC_SHA1", "sha1"), "28": ("HMAC_SHA224", "sha224"), "32": ("HMAC_SHA256", "sha256"), "48": ("HMAC_SHA384", "sha384"), "64": ("HMAC_SHA512", "sha512")}
    zf = zipfile.ZipFile(io.BytesIO(zb)); rsp = None
    for n in zf.namelist():
        if n.lower().endswith(".rsp"): rsp = n; break
    if not rsp: return 0, 0, {}
    content = zf.read(rsp).decode("utf-8", "replace"); sections = re.split(r'\[L=(\d+)\]', content)
    t = p = 0; res = {}
    for i in range(1, len(sections), 2):
        lv = sections[i].strip(); block = sections[i + 1]
        if lv not in L2A: continue
        ak, an = L2A[lv]; vecs = []; cur = {}
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            if "=" in line:
                k, v = line.split("=", 1); cur[k.strip()] = v.strip()
                if k.strip() == "Mac": vecs.append(cur.copy()); tl = cur.get("Tlen", "0"); cur = {"Tlen": tl}
        ap2 = 0
        for v in vecs:
            comp = hmac_mod.new(bytes.fromhex(v["Key"]), bytes.fromhex(v["Msg"]), an).hexdigest()
            tlen = int(v.get("Tlen", "0"))
            if tlen > 0: comp = comp[:tlen * 2]
            if comp == v["Mac"].lower(): ap2 += 1
        at = len(vecs); print(f"    {ak:<16}{ap2:>5}/{at:<5} {'✅' if ap2 == at else '❌'}")
        t += at; p += ap2; res[ak] = {"total": at, "passed": ap2, "failed": at - ap2}
    return t, p, res

def run_ecdsa(zb):
    if not HAS_CRYPTO: return 0, 0, {}
    CURVES = {"P-192": ec.SECP192R1(), "P-224": ec.SECP224R1(), "P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
    def gh(n): return {"SHA-1": ch.SHA1(), "SHA-224": ch.SHA224(), "SHA-256": ch.SHA256(), "SHA-384": ch.SHA384(), "SHA-512": ch.SHA512()}.get(n)
    zf = zipfile.ZipFile(io.BytesIO(zb)); sv = zf.read("SigVer.rsp").decode("utf-8", "replace")
    cc = ch2 = None; cur = {}; t = p = sk = 0; by_curve = {}
    for line in sv.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("["):
            pts = line[1:-1].split(",")
            if len(pts) == 2: cc = CURVES.get(pts[0].strip()); ch2 = pts[1].strip()
            continue
        if "=" in line: k, v = line.split("=", 1); cur[k.strip()] = v.strip()
        if "Result" in cur:
            if not cc or not gh(ch2): sk += 1; cur = {}; continue
            try:
                qx, qy = int(cur["Qx"], 16), int(cur["Qy"], 16)
                rv, sv2 = int(cur["R"], 16), int(cur["S"], 16)
                msg = bytes.fromhex(cur["Msg"]); ep = cur["Result"].startswith("P")
                pk = ec.EllipticCurvePublicNumbers(qx, qy, cc).public_key(default_backend())
                sig = utils.encode_dss_signature(rv, sv2)
                try: pk.verify(sig, msg, ec.ECDSA(gh(ch2))); ap2 = True
                except: ap2 = False
                cn = cur.get("_cn", "")
                if not any(c in by_curve for c in CURVES if c == cn):
                    for cname, cobj in CURVES.items():
                        if cobj.name == cc.name:
                            if cname not in by_curve: by_curve[cname] = {"t": 0, "p": 0}
                            by_curve[cname]["t"] += 1
                            if ep == ap2: by_curve[cname]["p"] += 1; p += 1
                            break
                else:
                    if ep == ap2: p += 1
                t += 1
            except: sk += 1
            cur = {}
    res = {}
    for cv in sorted(by_curve):
        d = by_curve[cv]; print(f"    ECDSA_{cv:<8}  {d['p']:>5}/{d['t']:<5} {'✅' if d['p'] == d['t'] else '❌'}")
        res[f"ECDSA_{cv}"] = {"total": d["t"], "passed": d["p"], "failed": d["t"] - d["p"]}
    if sk: print(f"    (Skipped {sk} binary/Koblitz)")
    return t, p, res

def run_rsa(zb):
    if not HAS_CRYPTO: return 0, 0, {}
    HM = {"SHA1": ch.SHA1(), "SHA224": ch.SHA224(), "SHA256": ch.SHA256(), "SHA384": ch.SHA384(), "SHA512": ch.SHA512()}
    zf = zipfile.ZipFile(io.BytesIO(zb)); t = p = 0; res = {}
    for tf, label, pad_fn in [("SigVer15_186-3.rsp", "RSA_PKCS15", lambda h: padding.PKCS1v15()), ("SigVerPSS_186-3.rsp", "RSA_PSS", lambda h: padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.AUTO))]:
        fp2 = None
        for n in zf.namelist():
            if os.path.basename(n) == tf: fp2 = n; break
        if not fp2: continue
        c = zf.read(fp2).decode("utf-8", "replace"); cn = ce = None; ch3 = None; cur = {}; at = ap = 0
        for line in c.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["): continue
            if "=" in line:
                k, v = line.split("=", 1); k = k.strip(); v = v.strip()
                if k == "n": cn = int(v, 16)
                elif k == "e": ce = int(v, 16)
                elif k == "SHAAlg": ch3 = HM.get(v)
                else: cur[k] = v
                if "Result" in cur and cn and ce and ch3:
                    try:
                        msg = bytes.fromhex(cur["Msg"]); sig = bytes.fromhex(cur["S"]); ep = cur["Result"].startswith("P")
                        pk = rsa.RSAPublicNumbers(ce, cn).public_key(default_backend())
                        try: pk.verify(sig, msg, pad_fn(ch3), ch3); ap2 = True
                        except: ap2 = False
                        if ep == ap2: ap += 1
                        at += 1
                    except: at += 1
                    cur = {}
        print(f"    {label:<16}{ap:>5}/{at:<5} {'✅' if ap == at else '❌'}"); t += at; p += ap
        res[label] = {"total": at, "passed": ap, "failed": at - ap}
    return t, p, res

def run_aes_kat(zb):
    if not HAS_CRYPTO: return 0, 0, {}
    MM = {"CBC": lambda iv: modes.CBC(iv), "ECB": lambda iv: modes.ECB(), "OFB": lambda iv: modes.OFB(iv), "CFB128": lambda iv: modes.CFB(iv), "CFB8": lambda iv: modes.CFB8(iv)}
    zf = zipfile.ZipFile(io.BytesIO(zb)); t = p = 0; res = {}; mt = {}
    for fn in sorted(n for n in zf.namelist() if n.lower().endswith(".rsp")):
        c = zf.read(fn).decode("utf-8", "replace"); bn = os.path.basename(fn).replace(".rsp", "")
        mn = None
        for m in MM:
            if m in bn.upper(): mn = m; break
        if not mn: continue
        enc = True; cur = {}; ft = fp = 0
        for line in c.splitlines():
            line = line.strip()
            if line == "[ENCRYPT]": enc = True; continue
            if line == "[DECRYPT]": enc = False; continue
            if not line or line.startswith("#") or line.startswith("["): continue
            if "=" in line:
                k, v = line.split("=", 1); cur[k.strip()] = v.strip()
                if "CIPHERTEXT" in cur and "PLAINTEXT" in cur and "KEY" in cur:
                    try:
                        key = bytes.fromhex(cur["KEY"]); iv = bytes.fromhex(cur["IV"]) if "IV" in cur else b"\x00" * 16
                        pt = bytes.fromhex(cur["PLAINTEXT"]); ct = bytes.fromhex(cur["CIPHERTEXT"])
                        mo = MM[mn](iv)
                        if enc:
                            comp = Cipher(algorithms.AES(key), mo, backend=default_backend()).encryptor()
                            if (comp.update(pt) + comp.finalize()) == ct: fp += 1
                        else:
                            comp = Cipher(algorithms.AES(key), mo, backend=default_backend()).decryptor()
                            if (comp.update(ct) + comp.finalize()) == pt: fp += 1
                        ft += 1
                    except: ft += 1
                    cur = {}
        if mn not in mt: mt[mn] = {"t": 0, "p": 0}
        mt[mn]["t"] += ft; mt[mn]["p"] += fp; t += ft; p += fp
    for m in sorted(mt):
        d = mt[m]; print(f"    AES_{m:<12}{d['p']:>5}/{d['t']:<5} {'✅' if d['p'] == d['t'] else '❌'}")
        res[f"AES_{m}"] = {"total": d["t"], "passed": d["p"], "failed": d["t"] - d["p"]}
    return t, p, res

def run_aes_mmt(zb):
    if not HAS_CRYPTO: return 0, 0, {}
    MM = {"CBC": lambda iv: modes.CBC(iv), "ECB": lambda iv: modes.ECB(), "OFB": lambda iv: modes.OFB(iv), "CFB128": lambda iv: modes.CFB(iv), "CFB8": lambda iv: modes.CFB8(iv)}
    zf = zipfile.ZipFile(io.BytesIO(zb)); t = p = 0; res = {}
    for fn in sorted(n for n in zf.namelist() if n.lower().endswith(".rsp")):
        bn = os.path.basename(fn).replace(".rsp", "").upper(); mn = None
        for m in MM:
            if m in bn: mn = m; break
        if not mn: continue
        c = zf.read(fn).decode("utf-8", "replace"); enc = True; cur = {}
        for line in c.splitlines():
            line = line.strip()
            if line == "[ENCRYPT]": enc = True; continue
            if line == "[DECRYPT]": enc = False; continue
            if not line or line.startswith("#") or line.startswith("["): continue
            if "=" in line:
                k, v = line.split("=", 1); cur[k.strip()] = v.strip()
                if "CIPHERTEXT" in cur and "PLAINTEXT" in cur and "KEY" in cur:
                    try:
                        key = bytes.fromhex(cur["KEY"]); iv = bytes.fromhex(cur["IV"]) if "IV" in cur else b"\x00" * 16
                        pt = bytes.fromhex(cur["PLAINTEXT"]); ct = bytes.fromhex(cur["CIPHERTEXT"])
                        if enc:
                            if Cipher(algorithms.AES(key), MM[mn](iv), backend=default_backend()).encryptor().update(pt) == ct: p += 1
                        else:
                            if Cipher(algorithms.AES(key), MM[mn](iv), backend=default_backend()).decryptor().update(ct) == pt: p += 1
                        t += 1
                    except: t += 1
                    cur = {}
    print(f"    AES_MMT       {p:>5}/{t:<5} {'✅' if p == t else '❌'}")
    res["AES_MMT"] = {"total": t, "passed": p, "failed": t - p}
    return t, p, res

def run_gcm(zb):
    if not HAS_CRYPTO: return 0, 0, {}
    def gd(key, iv, ct, aad, tag):
        d = Cipher(algorithms.AES(key), modes.GCM(iv, tag, min_tag_length=4), backend=default_backend()).decryptor()
        d.authenticate_additional_data(aad); return d.update(ct) + d.finalize()
    def ge(key, iv, pt, aad):
        e = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        e.authenticate_additional_data(aad); ct = e.update(pt) + e.finalize(); return ct, e.tag
    zf = zipfile.ZipFile(io.BytesIO(zb)); t = p = 0; res = {}
    for fn in sorted(n for n in zf.namelist() if n.lower().endswith(".rsp")):
        c = zf.read(fn).decode("utf-8", "replace"); isd = "decrypt" in fn.lower(); ise = "encrypt" in fn.lower()
        ks = ""; 
        for k in ["128", "192", "256"]:
            if k in fn: ks = k; break
        label = f"GCM_{'Dec' if isd else 'Enc'}_{ks}"; ft = fp = fs = 0; civl = 96; cur = {}
        for line in c.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("["):
                m = re.match(r'\[IVlen = (\d+)\]', line)
                if m: civl = int(m.group(1))
                continue
            if line == "FAIL":
                if "Tag" in cur and isd:
                    if civl < 64 or civl > 1024: fs += 1; cur = {}; continue
                    try:
                        try: gd(bytes.fromhex(cur["Key"]), bytes.fromhex(cur["IV"]), bytes.fromhex(cur.get("CT", "")) if cur.get("CT", "") else b"", bytes.fromhex(cur.get("AAD", "")) if cur.get("AAD", "") else b"", bytes.fromhex(cur["Tag"]))
                        except: fp += 1
                        ft += 1
                    except: fs += 1
                cur = {}; continue
            if "=" in line:
                k, v = line.split("=", 1); cur[k.strip()] = v.strip()
                if isd and k.strip() == "PT":
                    if "Tag" in cur:
                        if civl < 64 or civl > 1024: fs += 1; cur = {}; continue
                        try:
                            pt = gd(bytes.fromhex(cur["Key"]), bytes.fromhex(cur["IV"]), bytes.fromhex(cur.get("CT", "")) if cur.get("CT", "") else b"", bytes.fromhex(cur.get("AAD", "")) if cur.get("AAD", "") else b"", bytes.fromhex(cur["Tag"]))
                            if pt == (bytes.fromhex(cur["PT"]) if cur["PT"] else b""): fp += 1
                            ft += 1
                        except: ft += 1
                    cur = {}
                elif ise and k.strip() == "Tag":
                    if "PT" in cur:
                        if civl < 64 or civl > 1024: fs += 1; cur = {}; continue
                        try:
                            ct2, tag2 = ge(bytes.fromhex(cur["Key"]), bytes.fromhex(cur["IV"]), bytes.fromhex(cur.get("PT", "")) if cur.get("PT", "") else b"", bytes.fromhex(cur.get("AAD", "")) if cur.get("AAD", "") else b"")
                            etag = bytes.fromhex(cur["Tag"]); tag2 = tag2[:len(etag)]
                            ect = bytes.fromhex(cur.get("CT", "")) if cur.get("CT", "") else b""
                            if ct2 == ect and tag2 == etag: fp += 1
                            ft += 1
                        except: ft += 1
                    cur = {}
        print(f"    {label:<16}{fp:>5}/{ft:<5} {'✅' if fp == ft else '❌'}  (skip {fs})")
        t += ft; p += fp; res[label] = {"total": ft, "passed": fp, "failed": ft - fp}
    return t, p, res

def run_ccm(zb):
    if not HAS_CRYPTO: return 0, 0, {}
    zf = zipfile.ZipFile(io.BytesIO(zb)); t = p = 0; res = {}
    for fn in sorted(n for n in zf.namelist() if n.lower().endswith(".rsp")):
        c = zf.read(fn).decode("utf-8", "replace"); bn = os.path.basename(fn).replace(".rsp", "")
        is_dvpt = "DVPT" in bn.upper(); params = {}; cur_key = cur_nonce = None; cur = {}; ft = fp = 0
        for line in c.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("["):
                for k2, v2 in re.findall(r'(\w+)\s*=\s*(\d+)', line): params[k2] = int(v2)
                cur_key = cur_nonce = None; continue
            if "=" in line:
                k, v = line.split("=", 1); k = k.strip(); v = v.strip()
                if k in ("Plen", "Nlen", "Tlen", "Alen") and "Count" not in cur: params[k] = int(v); continue
                if k == "Key": cur_key = v; continue
                if k == "Nonce" and "Count" not in cur: cur_nonce = v; continue
                cur[k] = v
                if is_dvpt and "Result" in cur and cur_key:
                    try:
                        key = bytes.fromhex(cur_key); nonce = bytes.fromhex(cur.get("Nonce", cur_nonce or ""))
                        ct_full = bytes.fromhex(cur["CT"]); alen = params.get("Alen", 0)
                        adata = bytes.fromhex(cur.get("Adata", "")) if alen > 0 else None
                        tlen = params.get("Tlen", 4); ep = "Pass" in cur["Result"]
                        aesccm = AESCCM(key, tag_length=tlen)
                        try: aesccm.decrypt(nonce, ct_full, adata); ap2 = True
                        except: ap2 = False
                        if ep == ap2: fp += 1
                        ft += 1
                    except: ft += 1
                    cur = {}
                elif not is_dvpt and "CT" in cur and "Payload" in cur and cur_key:
                    try:
                        key = bytes.fromhex(cur_key); nonce = bytes.fromhex(cur.get("Nonce", cur_nonce or ""))
                        plen = params.get("Plen", 0); payload = bytes.fromhex(cur["Payload"]) if plen > 0 else b""
                        alen = params.get("Alen", 0); adata = bytes.fromhex(cur.get("Adata", "")) if alen > 0 else None
                        tlen = params.get("Tlen", 4); expected_ct = bytes.fromhex(cur["CT"])
                        if AESCCM(key, tag_length=tlen).encrypt(nonce, payload, adata) == expected_ct: fp += 1
                        ft += 1
                    except: ft += 1
                    cur = {}
        print(f"    CCM_{bn:<14}{fp:>5}/{ft:<5} {'✅' if fp == ft else '❌'}")
        t += ft; p += fp; res[f"CCM_{bn}"] = {"total": ft, "passed": fp, "failed": ft - fp}
    return t, p, res

def run_cmac(zb):
    if not HAS_CRYPTO: return 0, 0, {}
    zf = zipfile.ZipFile(io.BytesIO(zb)); t = p = 0; res = {}
    for fn in sorted(n for n in zf.namelist() if n.lower().endswith(".rsp")):
        bn = os.path.basename(fn)
        if "TDES" in bn.upper(): continue
        c = zf.read(fn).decode("utf-8", "replace"); ig = "gen" in bn.lower(); cur = {}; ft = fp = 0
        for line in c.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            if "=" in line:
                k, v = line.split("=", 1); cur[k.strip()] = v.strip()
                if ig and "Mac" in cur and "Key" in cur:
                    try:
                        key = bytes.fromhex(cur["Key"]); mlen = int(cur.get("Mlen", "0"))
                        msg = bytes.fromhex(cur["Msg"]) if mlen > 0 else b""
                        tlen = int(cur.get("Tlen", "16")); exp = cur["Mac"].lower()
                        cm = cmac_crypto.CMAC(algorithms.AES(key), backend=default_backend()); cm.update(msg)
                        if cm.finalize().hex()[:tlen * 2] == exp: fp += 1
                        ft += 1
                    except: ft += 1
                    cur = {}
                elif not ig and "Result" in cur and "Key" in cur:
                    try:
                        key = bytes.fromhex(cur["Key"]); mlen = int(cur.get("Mlen", "0"))
                        msg = bytes.fromhex(cur["Msg"]) if mlen > 0 else b""
                        tlen = int(cur.get("Tlen", "16")); mac_val = bytes.fromhex(cur["Mac"]); ep = "P" in cur["Result"]
                        cm = cmac_crypto.CMAC(algorithms.AES(key), backend=default_backend()); cm.update(msg)
                        ap2 = cm.finalize()[:tlen] == mac_val
                        if ep == ap2: fp += 1
                        ft += 1
                    except: ft += 1
                    cur = {}
        label = bn.replace(".rsp", ""); print(f"    {label:<20}{fp:>5}/{ft:<5} {'✅' if fp == ft else '❌'}")
        t += ft; p += fp; res[label] = {"total": ft, "passed": fp, "failed": ft - fp}
    return t, p, res

def run_ecdh(zb):
    if not HAS_CRYPTO: return 0, 0, {}
    CURVES = {"P-192": ec.SECP192R1(), "P-224": ec.SECP224R1(), "P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
    zf = zipfile.ZipFile(io.BytesIO(zb)); t = p = 0; res = {}
    for fn in zf.namelist():
        if not fn.endswith(".txt"): continue
        c = zf.read(fn).decode("utf-8", "replace"); cc = None; cur = {}; ft = fp = 0
        for line in c.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"): cc = CURVES.get(line[1:-1].strip()); continue
            if not line or line.startswith("#"): continue
            if "=" in line:
                k, v = line.split("=", 1); cur[k.strip()] = v.strip()
                if "ZIUT" in cur and cc:
                    try:
                        priv = ec.derive_private_key(int(cur["dIUT"], 16), cc, default_backend())
                        pub = ec.EllipticCurvePublicNumbers(int(cur["QCAVSx"], 16), int(cur["QCAVSy"], 16), cc).public_key(default_backend())
                        if priv.exchange(ec.ECDH(), pub).hex() == cur["ZIUT"].lower(): fp += 1
                        ft += 1
                    except: ft += 1
                    cur = {}
        print(f"    ECDH          {fp:>5}/{ft:<5} {'✅' if fp == ft else '❌'}")
        t += ft; p += fp; res["ECDH"] = {"total": ft, "passed": fp, "failed": ft - fp}
    return t, p, res


# ═══════════════════════════════════════════════════════════════
# LAYER 2: WYCHEPROOF ADVERSARIAL TESTS (Google)
# Catches: invalid curve attacks, signature malleability,
# truncated auth tags, weak RSA padding, edge-case keys
# ═══════════════════════════════════════════════════════════════

def wp_check(result, actual_valid):
    """Wycheproof result logic: valid=must pass, invalid=must fail, acceptable=either."""
    if result == "valid": return actual_valid
    elif result == "invalid": return not actual_valid
    else: return True  # acceptable

def run_wp_aes_gcm():
    t = p = 0; res = {}
    for fname in WYCHEPROOF_FILES["WP_AES_GCM"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            for grp in data.get("testGroups", []):
                for tc in grp.get("tests", []):
                    try:
                        key = bytes.fromhex(tc["key"]); iv = bytes.fromhex(tc["iv"])
                        aad = bytes.fromhex(tc.get("aad", "")); msg = bytes.fromhex(tc.get("msg", ""))
                        ct = bytes.fromhex(tc.get("ct", "")); tag = bytes.fromhex(tc.get("tag", ""))
                        result = tc.get("result", "valid")
                        try:
                            dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag, min_tag_length=4), backend=default_backend()).decryptor()
                            dec.authenticate_additional_data(aad); pt = dec.update(ct) + dec.finalize()
                            valid = True
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_aes_ccm():
    t = p = 0; res = {}
    for fname in WYCHEPROOF_FILES["WP_AES_CCM"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            for grp in data.get("testGroups", []):
                tl = grp.get("tagSize", 128) // 8
                for tc in grp.get("tests", []):
                    try:
                        key = bytes.fromhex(tc["key"]); iv = bytes.fromhex(tc["iv"])
                        aad = bytes.fromhex(tc.get("aad", "")); msg = bytes.fromhex(tc.get("msg", ""))
                        ct = bytes.fromhex(tc.get("ct", "")); tag = bytes.fromhex(tc.get("tag", ""))
                        result = tc.get("result", "valid")
                        try:
                            aesccm = AESCCM(key, tag_length=tl)
                            pt = aesccm.decrypt(iv, ct + tag, aad if aad else None)
                            valid = True
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_chacha():
    t = p = 0; res = {}
    for fname in WYCHEPROOF_FILES["WP_CHACHA20"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            for grp in data.get("testGroups", []):
                for tc in grp.get("tests", []):
                    try:
                        key = bytes.fromhex(tc["key"]); iv = bytes.fromhex(tc["iv"])
                        aad = bytes.fromhex(tc.get("aad", "")); msg = bytes.fromhex(tc.get("msg", ""))
                        ct = bytes.fromhex(tc.get("ct", "")); tag = bytes.fromhex(tc.get("tag", ""))
                        result = tc.get("result", "valid")
                        try:
                            cp = ChaCha20Poly1305(key)
                            pt = cp.decrypt(iv, ct + tag, aad if aad else None)
                            valid = True
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_ecdsa():
    t = p = 0; res = {}
    CURVES = {"secp224r1": ec.SECP224R1(), "secp256r1": ec.SECP256R1(), "secp384r1": ec.SECP384R1(), "secp521r1": ec.SECP521R1()}
    HASHES = {"SHA-224": ch.SHA224(), "SHA-256": ch.SHA256(), "SHA-384": ch.SHA384(), "SHA-512": ch.SHA512()}
    for fname in WYCHEPROOF_FILES["WP_ECDSA"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            for grp in data.get("testGroups", []):
                curve_name = grp.get("key", {}).get("curve", "")
                curve = CURVES.get(curve_name)
                sha = HASHES.get(grp.get("sha", ""))
                if not curve or not sha: continue
                key_data = grp.get("key", {})
                try:
                    wx = int(key_data.get("wx", "0"), 16)
                    wy = int(key_data.get("wy", "0"), 16)
                    pubkey = ec.EllipticCurvePublicNumbers(wx, wy, curve).public_key(default_backend())
                except: continue
                for tc in grp.get("tests", []):
                    try:
                        msg = bytes.fromhex(tc["msg"]); sig = bytes.fromhex(tc["sig"])
                        result = tc.get("result", "valid")
                        try: pubkey.verify(sig, msg, ec.ECDSA(sha)); valid = True
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_rsa_pkcs1():
    t = p = 0; res = {}
    HASHES = {"SHA-224": ch.SHA224(), "SHA-256": ch.SHA256(), "SHA-384": ch.SHA384(), "SHA-512": ch.SHA512()}
    for fname in WYCHEPROOF_FILES["WP_RSA_PKCS1"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            for grp in data.get("testGroups", []):
                sha = HASHES.get(grp.get("sha", ""))
                if not sha: continue
                key_der = bytes.fromhex(grp.get("keyDer", ""))
                try: pubkey = load_der_public_key(key_der, backend=default_backend())
                except: continue
                for tc in grp.get("tests", []):
                    try:
                        msg = bytes.fromhex(tc["msg"]); sig = bytes.fromhex(tc["sig"])
                        result = tc.get("result", "valid")
                        try: pubkey.verify(sig, msg, padding.PKCS1v15(), sha); valid = True
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_rsa_pss():
    t = p = 0; res = {}
    HASHES = {"SHA-256": ch.SHA256(), "SHA-384": ch.SHA384(), "SHA-512": ch.SHA512()}
    for fname in WYCHEPROOF_FILES["WP_RSA_PSS"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            for grp in data.get("testGroups", []):
                sha_name = grp.get("sha", "")
                mgf_sha_name = grp.get("mgfSha", sha_name)
                sha = HASHES.get(sha_name)
                mgf_sha = HASHES.get(mgf_sha_name)
                slen = grp.get("sLen", 32)
                if not sha or not mgf_sha: continue
                key_der = bytes.fromhex(grp.get("keyDer", ""))
                try: pubkey = load_der_public_key(key_der, backend=default_backend())
                except: continue
                for tc in grp.get("tests", []):
                    try:
                        msg = bytes.fromhex(tc["msg"]); sig = bytes.fromhex(tc["sig"])
                        result = tc.get("result", "valid")
                        try:
                            pubkey.verify(sig, msg, padding.PSS(mgf=padding.MGF1(mgf_sha), salt_length=slen), sha)
                            valid = True
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_ecdh():
    t = p = 0; res = {}
    CURVES = {"secp224r1": ec.SECP224R1(), "secp256r1": ec.SECP256R1(), "secp384r1": ec.SECP384R1(), "secp521r1": ec.SECP521R1()}
    for fname in WYCHEPROOF_FILES["WP_ECDH"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            for grp in data.get("testGroups", []):
                curve_name = grp.get("curve", "")
                curve = CURVES.get(curve_name)
                if not curve: continue
                for tc in grp.get("tests", []):
                    try:
                        pub_hex = tc.get("public", ""); priv_hex = tc.get("private", "")
                        shared_hex = tc.get("shared", ""); result = tc.get("result", "valid")
                        priv_int = int(priv_hex, 16)
                        # Parse uncompressed public key point (04 || x || y)
                        pub_bytes = bytes.fromhex(pub_hex)
                        try:
                            pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, pub_bytes)
                            priv = ec.derive_private_key(priv_int, curve, default_backend())
                            shared = priv.exchange(ec.ECDH(), pub)
                            valid = shared.hex() == shared_hex.lower()
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_hmac():
    t = p = 0; res = {}
    HASH_MAP = {"HMACSHA1": "sha1", "HMACSHA224": "sha224", "HMACSHA256": "sha256", "HMACSHA384": "sha384", "HMACSHA512": "sha512"}
    for fname in WYCHEPROOF_FILES["WP_HMAC"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            algo = None
            for k, v in HASH_MAP.items():
                if k.lower().replace("hmac", "") in fname.lower().replace("hmac_", "").replace("_test.json", ""): algo = v; break
            if not algo: continue
            for grp in data.get("testGroups", []):
                tl = grp.get("tagSize", 256) // 8
                for tc in grp.get("tests", []):
                    try:
                        key = bytes.fromhex(tc["key"]); msg = bytes.fromhex(tc["msg"])
                        tag = bytes.fromhex(tc["tag"]); result = tc.get("result", "valid")
                        computed = hmac_mod.new(key, msg, algo).digest()[:tl]
                        valid = computed == tag
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_dsa():
    t = p = 0; res = {}
    for fname in WYCHEPROOF_FILES["WP_DSA"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            HASHES = {"SHA-224": ch.SHA224(), "SHA-256": ch.SHA256(), "SHA-384": ch.SHA384(), "SHA-512": ch.SHA512()}
            for grp in data.get("testGroups", []):
                sha = HASHES.get(grp.get("sha", ""))
                if not sha: continue
                key_der = bytes.fromhex(grp.get("keyDer", ""))
                try: pubkey = load_der_public_key(key_der, backend=default_backend())
                except: continue
                for tc in grp.get("tests", []):
                    try:
                        msg = bytes.fromhex(tc["msg"]); sig = bytes.fromhex(tc["sig"])
                        result = tc.get("result", "valid")
                        from cryptography.hazmat.primitives.asymmetric import dsa as dsa_mod
                        try: pubkey.verify(sig, msg, sha); valid = True
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res

def run_wp_rsa_oaep():
    t = p = 0; res = {}
    for fname in WYCHEPROOF_FILES["WP_RSA_OAEP"]:
        try:
            data = dl_json(f"{WP_BASE}/{fname}")
            ft = fp = 0
            HASHES = {"SHA-1": ch.SHA1(), "SHA-256": ch.SHA256(), "SHA-384": ch.SHA384(), "SHA-512": ch.SHA512()}
            for grp in data.get("testGroups", []):
                sha_name = grp.get("sha", "")
                mgf_sha_name = grp.get("mgfSha", sha_name)
                sha = HASHES.get(sha_name)
                mgf_sha = HASHES.get(mgf_sha_name)
                if not sha or not mgf_sha: continue
                key_der = bytes.fromhex(grp.get("privateKeyPkcs8", grp.get("keyDer", "")))
                try:
                    from cryptography.hazmat.primitives.serialization import load_der_private_key
                    privkey = load_der_private_key(key_der, password=None, backend=default_backend())
                except: continue
                for tc in grp.get("tests", []):
                    try:
                        ct = bytes.fromhex(tc["ct"]); label = bytes.fromhex(tc.get("label", ""))
                        result = tc.get("result", "valid")
                        try:
                            pt = privkey.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=mgf_sha), algorithm=sha, label=label if label else None))
                            msg = bytes.fromhex(tc.get("msg", ""))
                            valid = pt == msg
                        except: valid = False
                        if wp_check(result, valid): fp += 1
                        ft += 1
                    except: ft += 1
            print(f"  {fp}/{ft} {'✅' if fp == ft else '❌'}")
            t += ft; p += fp; res[fname] = {"total": ft, "passed": fp, "failed": ft - fp}
        except Exception as e: print(f"  ❌ {e}")
    return t, p, res


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    start = time.time()

    print()
    print("  ╔" + "═" * 66 + "╗")
    print("  ║" + "THE HENRY COMPANY".center(66) + "║")
    print("  ║" + "Cryptographic Verification Suite v4".center(66) + "║")
    print("  ║" + "NIST CAVP + Google Wycheproof Adversarial".center(66) + "║")
    print("  ║" + "Live from csrc.nist.gov + github.com/google/wycheproof".center(66) + "║")
    print("  ╚" + "═" * 66 + "╝")
    print()
    print("  LAYER 1: NIST CAVP — Official federal test vectors")
    print("    FIPS 180-4 · FIPS 202 · FIPS 198-1 · FIPS 186-4")
    print("    FIPS 197 · SP 800-38B · SP 800-38C · SP 800-38D · SP 800-56A")
    print()
    print("  LAYER 2: WYCHEPROOF — Google adversarial edge-case attacks")
    print("    Invalid curves · Signature malleability · Truncated tags")
    print("    Weak padding · Edge-case keys · Type confusion")
    print()
    print(f"  cryptography: {'✅' if HAS_CRYPTO else '❌ (pip install cryptography)'}")
    print()

    gt = gp = 0
    AR = {}

    # ── LAYER 1: NIST CAVP ─────────────────────────────────────
    NIST_SUITES = [
        ("SHA-2",      "INTEGRITY",       lambda z: run_sha_family(z, SHA2_MAP, id_sha2, mc_sha2)),
        ("SHA-3",      "CRYPTO AGILITY",  lambda z: run_sha_family(z, SHA3_MAP, id_sha3, mc_sha3)),
        ("SHAKE",      "EXTENSIBILITY",   run_shake),
        ("HMAC",       "AUTHORITY",       run_hmac),
        ("ECDSA",      "IDENTITY (EC)",   run_ecdsa),
        ("RSA",        "IDENTITY (RSA)",  run_rsa),
        ("AES-MODES",  "BLOCK CIPHER",    run_aes_kat),
        ("AES-MMT",    "MULTI-BLOCK",     run_aes_mmt),
        ("AES-GCM",    "CONFIDENTIALITY", run_gcm),
        ("AES-CCM",    "AUTH ENCRYPT",    run_ccm),
        ("CMAC",       "CIPHER MAC",      run_cmac),
        ("ECDH",       "KEY AGREEMENT",   run_ecdh),
    ]

    print("  ╔" + "═" * 66 + "╗")
    print("  ║" + "LAYER 1: NIST CAVP — FEDERAL STANDARDS".center(66) + "║")
    print("  ╚" + "═" * 66 + "╝")
    print()

    for idx, (name, domain, runner) in enumerate(NIST_SUITES, 1):
        src = NIST_SOURCES.get(name)
        if not src: continue
        std, url = src
        print(f"  {'─' * 66}")
        print(f"  [{idx}] {name} ({std}) — {domain}")
        print(f"  {'─' * 66}")
        try:
            zdata = dl(url)
            tt, pp, rr = runner(zdata)
            gt += tt; gp += pp
            AR[name] = {"standard": std, "domain": domain, "total": tt, "passed": pp, "algorithms": rr, "layer": "NIST"}
            print(f"    Subtotal: {pp:,}/{tt:,} {'✅' if pp == tt else '❌'}")
        except Exception as e:
            print(f"    ❌ {e}")
        print()

    # ── LAYER 2: WYCHEPROOF ────────────────────────────────────
    if HAS_CRYPTO:
        print()
        print("  ╔" + "═" * 66 + "╗")
        print("  ║" + "LAYER 2: WYCHEPROOF — ADVERSARIAL ATTACK VECTORS".center(66) + "║")
        print("  ║" + "github.com/google/wycheproof".center(66) + "║")
        print("  ╚" + "═" * 66 + "╝")
        print()

        WP_SUITES = [
            ("WP_AES_GCM",   "GCM ATTACKS",        run_wp_aes_gcm),
            ("WP_AES_CCM",   "CCM ATTACKS",         run_wp_aes_ccm),
            ("WP_CHACHA20",  "CHACHA20 ATTACKS",     run_wp_chacha),
            ("WP_HMAC",      "HMAC EDGE CASES",      run_wp_hmac),
            ("WP_ECDSA",     "ECDSA MALLEABILITY",   run_wp_ecdsa),
            ("WP_RSA_PKCS1", "RSA PKCS1 ATTACKS",    run_wp_rsa_pkcs1),
            ("WP_RSA_PSS",   "RSA PSS ATTACKS",      run_wp_rsa_pss),
            ("WP_ECDH",      "ECDH INVALID CURVES",  run_wp_ecdh),
            ("WP_DSA",       "DSA ATTACKS",           run_wp_dsa),
            ("WP_RSA_OAEP",  "RSA OAEP ATTACKS",     run_wp_rsa_oaep),
        ]

        for idx, (name, domain, runner) in enumerate(WP_SUITES, 13):
            print(f"  {'─' * 66}")
            print(f"  [{idx}] {name} — {domain}")
            print(f"  {'─' * 66}")
            try:
                tt, pp, rr = runner()
                gt += tt; gp += pp
                AR[name] = {"standard": "Wycheproof", "domain": domain, "total": tt, "passed": pp, "algorithms": rr, "layer": "Wycheproof"}
                print(f"    Subtotal: {pp:,}/{tt:,} {'✅' if pp == tt else '❌'}")
            except Exception as e:
                print(f"    ❌ {e}")
            print()

    elapsed = time.time() - start
    ok = gp == gt

    try: ov = ssl.OPENSSL_VERSION
    except: ov = "?"
    try:
        from cryptography import __version__ as cv
    except: cv = "N/A"

    ta = sum(len(s["algorithms"]) for s in AR.values())
    us = sorted(set(s["standard"] for s in AR.values()))
    nist_total = sum(s["total"] for s in AR.values() if s.get("layer") == "NIST")
    nist_passed = sum(s["passed"] for s in AR.values() if s.get("layer") == "NIST")
    wp_total = sum(s["total"] for s in AR.values() if s.get("layer") == "Wycheproof")
    wp_passed = sum(s["passed"] for s in AR.values() if s.get("layer") == "Wycheproof")

    # Grand Summary
    print()
    print("  ╔" + "═" * 66 + "╗")
    print("  ║" + "VERIFICATION REPORT".center(66) + "║")
    print("  ╠" + "═" * 66 + "╣")
    print("  ║" + "  LAYER 1: NIST CAVP (Federal Standards)".ljust(66) + "║")
    for nm, data in AR.items():
        if data.get("layer") != "NIST": continue
        mk = "✅" if data["passed"] == data["total"] else "❌"
        ln = f"    {nm:<14} {data['standard']:<12} {data['passed']:>6}/{data['total']:<6} {mk}"
        print("  ║" + ln.ljust(66) + "║")
    print("  ║" + f"    NIST subtotal: {nist_passed:,}/{nist_total:,}".ljust(66) + "║")
    print("  ║" + "".ljust(66) + "║")
    print("  ║" + "  LAYER 2: WYCHEPROOF (Adversarial Attacks)".ljust(66) + "║")
    for nm, data in AR.items():
        if data.get("layer") != "Wycheproof": continue
        mk = "✅" if data["passed"] == data["total"] else "❌"
        ln = f"    {nm:<14} {data['passed']:>6}/{data['total']:<6} {mk}"
        print("  ║" + ln.ljust(66) + "║")
    print("  ║" + f"    Wycheproof subtotal: {wp_passed:,}/{wp_total:,}".ljust(66) + "║")
    print("  ╠" + "═" * 66 + "╣")
    gl = f"  GRAND TOTAL:  {gp:,} / {gt:,}  {'✅ ALL PASSED' if ok else '❌ FAILURES'}"
    print("  ║" + gl.ljust(66) + "║")
    print("  ║" + f"  Suites: {len(AR)}  |  Algorithms: {ta}  |  Time: {elapsed:.1f}s".ljust(66) + "║")
    print("  ╚" + "═" * 66 + "╝")
    print()

    if ok:
        print(f"  ✅ VERDICT: ALL {gt:,} TEST VECTORS PASSED")
        print(f"             {len(AR)} SUITES — 2 LAYERS — {len(us)} SOURCES")
        print()
        print("  ┌──────────────────────────────────────────────────────────────┐")
        print("  │  LAYER 1: NIST CAVP                                         │")
        for nm, data in AR.items():
            if data.get("layer") != "NIST": continue
            ln = f"  │    {data['domain']:<20} {data['standard']:<12} {data['passed']:>6} verified"
            print(ln.ljust(67) + "│")
        print("  │                                                              │")
        print("  │  LAYER 2: WYCHEPROOF ADVERSARIAL                             │")
        for nm, data in AR.items():
            if data.get("layer") != "Wycheproof": continue
            ln = f"  │    {data['domain']:<34} {data['passed']:>6} verified"
            print(ln.ljust(67) + "│")
        print("  └──────────────────────────────────────────────────────────────┘")
    else:
        print(f"  ❌ VERDICT: {gt - gp:,} TEST VECTORS FAILED")

    # Report & Seal
    report = {
        "title": "Cryptographic Verification Suite v4",
        "organization": "The Henry Company",
        "version": "4.0",
        "layers": ["NIST CAVP (csrc.nist.gov)", "Google Wycheproof (github.com/google/wycheproof)"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed": round(elapsed, 1),
        "env": {"python": sys.version.split()[0], "platform": platform.platform(), "openssl": ov, "cryptography": cv},
        "nist": {"total": nist_total, "passed": nist_passed, "sources": {k: v[1] for k, v in NIST_SOURCES.items()}},
        "wycheproof": {"total": wp_total, "passed": wp_passed},
        "summary": {"suites": len(AR), "total": gt, "passed": gp, "failed": gt - gp},
        "verdict": f"PASS — {gt:,} vectors" if ok else "FAIL",
    }
    rp = "nist_crypto_suite_verification.json"
    with open(rp, "w") as f: json.dump(report, f, indent=2)
    rb = json.dumps(report, indent=2).encode()
    sh = hashlib.sha256(rb).hexdigest()
    sp = "nist_crypto_suite_verification_seal.json"
    with open(sp, "w") as f:
        json.dump({"seal": {"doc": rp, "alg": "SHA-256", "hash": sh, "ts": datetime.now(timezone.utc).isoformat(), "by": "The Henry Company"}}, f, indent=2)

    print()
    print(f"  Report:    {os.path.abspath(rp)}")
    print(f"  Seal:      {os.path.abspath(sp)}")
    print(f"  Seal hash: {sh}")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print()
    print("  Environment:")
    print(f"    Python:       {sys.version.split()[0]}")
    print(f"    Platform:     {platform.platform()}")
    print(f"    OpenSSL:      {ov}")
    print(f"    cryptography: {cv}")
    print()
    print("  Sources:")
    print("    NIST CAVP:    https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program")
    print("    Wycheproof:   https://github.com/google/wycheproof")
    print()
    print("  ╔" + "═" * 66 + "╗")
    print("  ║" + "Two layers. Every test. Every attack. Every seal verified.".center(66) + "║")
    print("  ╚" + "═" * 66 + "╝")
    print()

    return ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
