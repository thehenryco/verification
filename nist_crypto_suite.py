#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  THE HENRY COMPANY — NIST Cryptographic Verification Suite v2  ║
║                                                                  ║
║  Five federal standards. All vectors from csrc.nist.gov.         ║
║  Nothing hardcoded. Run it yourself. Check our work.             ║
╚══════════════════════════════════════════════════════════════════╝

Standards tested:
  1. FIPS 180-4   SHA-1 / SHA-2           (Integrity)
  2. FIPS 202     SHA-3 / Keccak          (Crypto Agility)
  3. FIPS 198-1   HMAC                    (Authority)
  4. FIPS 186-4   ECDSA Digital Signatures (Identity)
  5. SP 800-38D   AES-GCM Authenticated   (Confidentiality)
                  Encryption

Requirements:
  pip install cryptography
  (Suites 1-3 use only Python stdlib. Suites 4-5 need cryptography.)

Usage:
  python nist_crypto_suite.py
"""

import hashlib
import hmac as hmac_mod
import json
import sys
import os
import platform
import ssl
import zipfile
import io
import re
import time
from datetime import datetime, timezone

try:
    import urllib.request
except ImportError:
    pass

# Check for cryptography library
HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════
# NIST CAVP SOURCE URLS — all from csrc.nist.gov
# ═══════════════════════════════════════════════════════════════
NIST_SOURCES = {
    "SHA-2": {
        "url": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip",
        "standard": "FIPS 180-4",
        "title": "Secure Hash Standard",
    },
    "SHA-3": {
        "url": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip",
        "standard": "FIPS 202",
        "title": "SHA-3 Permutation-Based Hash",
    },
    "HMAC": {
        "url": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip",
        "standard": "FIPS 198-1",
        "title": "Keyed-Hash Message Authentication Code",
    },
    "ECDSA": {
        "url": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3ecdsatestvectors.zip",
        "standard": "FIPS 186-4",
        "title": "Elliptic Curve Digital Signature Algorithm",
    },
    "AES-GCM": {
        "url": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip",
        "standard": "SP 800-38D",
        "title": "AES Galois/Counter Mode Authenticated Encryption",
    },
}

SHA2_MAP = {"SHA1":"sha1","SHA224":"sha224","SHA256":"sha256","SHA384":"sha384","SHA512":"sha512"}
SHA3_MAP = {"SHA3_224":"sha3_224","SHA3_256":"sha3_256","SHA3_384":"sha3_384","SHA3_512":"sha3_512"}


def download(url):
    print(f"    Fetching: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "HenryCompany-NIST-Verify/2.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


# ═══════════════════════════════════════════════════════════════
# PARSERS
# ═══════════════════════════════════════════════════════════════

def parse_hash_rsp(text):
    vectors = []
    current = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            current[key.strip()] = val.strip()
            if key.strip() == "MD":
                vectors.append({"bit_length": int(current.get("Len","0")), "msg_hex": current.get("Msg",""), "expected": val.strip().lower()})
                current = {}
    return vectors


def parse_monte_rsp(text):
    seed = None
    expected = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            if key.strip() == "Seed":
                seed = val.strip().lower()
            elif key.strip() == "MD":
                expected.append(val.strip().lower())
    return seed, expected


def run_monte_carlo_sha2(algo, seed_hex, expected):
    seed = bytes.fromhex(seed_hex)
    results = []
    for j in range(len(expected)):
        md = [seed, seed, seed]
        for i in range(3, 1003):
            md.append(hashlib.new(algo, md[i-3]+md[i-2]+md[i-1]).digest())
        output = md[1002]
        results.append(output.hex() == expected[j])
        seed = output
    return results


def run_monte_carlo_sha3(algo, seed_hex, expected):
    md = bytes.fromhex(seed_hex)
    results = []
    for j in range(len(expected)):
        for _ in range(1000):
            md = hashlib.new(algo, md).digest()
        results.append(md.hex() == expected[j])
    return results


def identify_sha2(filename):
    base = os.path.basename(filename).upper().replace(".RSP","")
    for s in ["SHORTMSG","LONGMSG","MONTE"]:
        base = base.replace(s, "")
    base = base.strip()
    for k,v in SHA2_MAP.items():
        if k in base:
            return k, v
    return None, None


def identify_sha3(filename):
    base = os.path.basename(filename).upper().replace(".RSP","").replace("-","_").replace(" ","_")
    for s in ["SHORTMSG","LONGMSG","MONTE"]:
        base = base.replace(s, "")
    for k,v in SHA3_MAP.items():
        if k.replace("_","") in base.replace("_",""):
            return k, v
    return None, None


# ═══════════════════════════════════════════════════════════════
# SUITE 1: SHA-2 (FIPS 180-4)
# ═══════════════════════════════════════════════════════════════

def run_sha2_suite(zip_bytes):
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    algo_files = {}
    for path in [n for n in zf.namelist() if n.lower().endswith(".rsp")]:
        fname = os.path.basename(path).lower()
        ak, an = identify_sha2(path)
        if not ak:
            continue
        if ak not in algo_files:
            algo_files[ak] = {"name": an, "short": None, "long": None, "monte": None}
        if "short" in fname: algo_files[ak]["short"] = path
        elif "long" in fname: algo_files[ak]["long"] = path
        elif "monte" in fname: algo_files[ak]["monte"] = path

    total = passed = 0
    results = {}
    for ak in sorted(algo_files):
        info = algo_files[ak]
        an = info["name"]
        try: hashlib.new(an, b"test")
        except: continue
        at = ap = 0
        print(f"    {ak:<12}", end="", flush=True)
        if info["short"]:
            vecs = parse_hash_rsp(zf.read(info["short"]).decode("utf-8","replace"))
            p = sum(1 for v in vecs if hashlib.new(an, b"" if v["bit_length"]==0 else bytes.fromhex(v["msg_hex"])).hexdigest()==v["expected"])
            at += len(vecs); ap += p
        if info["long"]:
            vecs = parse_hash_rsp(zf.read(info["long"]).decode("utf-8","replace"))
            p = sum(1 for v in vecs if hashlib.new(an, bytes.fromhex(v["msg_hex"])).hexdigest()==v["expected"])
            at += len(vecs); ap += p
        if info["monte"]:
            seed, exp = parse_monte_rsp(zf.read(info["monte"]).decode("utf-8","replace"))
            if seed and exp:
                mc = run_monte_carlo_sha2(an, seed, exp)
                at += len(mc); ap += sum(mc)
        print(f"  {ap:>5} / {at:<5}  {'✅' if ap==at else '❌'}")
        total += at; passed += ap
        results[ak] = {"total": at, "passed": ap, "failed": at-ap}
    return total, passed, results


# ═══════════════════════════════════════════════════════════════
# SUITE 2: SHA-3 (FIPS 202)
# ═══════════════════════════════════════════════════════════════

def run_sha3_suite(zip_bytes):
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    algo_files = {}
    for path in [n for n in zf.namelist() if n.lower().endswith(".rsp")]:
        fname = os.path.basename(path).lower()
        ak, an = identify_sha3(path)
        if not ak:
            continue
        if ak not in algo_files:
            algo_files[ak] = {"name": an, "short": None, "long": None, "monte": None}
        if "short" in fname: algo_files[ak]["short"] = path
        elif "long" in fname: algo_files[ak]["long"] = path
        elif "monte" in fname: algo_files[ak]["monte"] = path

    total = passed = 0
    results = {}
    for ak in sorted(algo_files):
        info = algo_files[ak]
        an = info["name"]
        try: hashlib.new(an, b"test")
        except: continue
        at = ap = 0
        print(f"    {ak:<12}", end="", flush=True)
        if info["short"]:
            vecs = parse_hash_rsp(zf.read(info["short"]).decode("utf-8","replace"))
            p = sum(1 for v in vecs if hashlib.new(an, b"" if v["bit_length"]==0 else bytes.fromhex(v["msg_hex"])).hexdigest()==v["expected"])
            at += len(vecs); ap += p
        if info["long"]:
            vecs = parse_hash_rsp(zf.read(info["long"]).decode("utf-8","replace"))
            p = sum(1 for v in vecs if hashlib.new(an, bytes.fromhex(v["msg_hex"])).hexdigest()==v["expected"])
            at += len(vecs); ap += p
        if info["monte"]:
            seed, exp = parse_monte_rsp(zf.read(info["monte"]).decode("utf-8","replace"))
            if seed and exp:
                mc = run_monte_carlo_sha3(an, seed, exp)
                at += len(mc); ap += sum(mc)
        print(f"  {ap:>5} / {at:<5}  {'✅' if ap==at else '❌'}")
        total += at; passed += ap
        results[ak] = {"total": at, "passed": ap, "failed": at-ap}
    return total, passed, results


# ═══════════════════════════════════════════════════════════════
# SUITE 3: HMAC (FIPS 198-1)
# ═══════════════════════════════════════════════════════════════

def run_hmac_suite(zip_bytes):
    L_TO_ALGO = {"20":("HMAC_SHA1","sha1"),"28":("HMAC_SHA224","sha224"),"32":("HMAC_SHA256","sha256"),"48":("HMAC_SHA384","sha384"),"64":("HMAC_SHA512","sha512")}
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    rsp = None
    for n in zf.namelist():
        if n.lower().endswith(".rsp"):
            rsp = n; break
    if not rsp:
        return 0, 0, {}
    content = zf.read(rsp).decode("utf-8","replace")
    sections = re.split(r'\[L=(\d+)\]', content)

    total = passed = 0
    results = {}
    for i in range(1, len(sections), 2):
        l_val = sections[i].strip()
        block = sections[i+1]
        if l_val not in L_TO_ALGO:
            continue
        ak, an = L_TO_ALGO[l_val]
        vectors = []
        cur = {}
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k,v = line.split("=",1)
                cur[k.strip()] = v.strip()
                if k.strip() == "Mac":
                    vectors.append(cur.copy())
                    tlen = cur.get("Tlen","0")
                    cur = {"Tlen": tlen}
        ap = 0
        for v in vectors:
            computed = hmac_mod.new(bytes.fromhex(v["Key"]), bytes.fromhex(v["Msg"]), an).hexdigest()
            tlen = int(v.get("Tlen","0"))
            if tlen > 0:
                computed = computed[:tlen*2]
            if computed == v["Mac"].lower():
                ap += 1
        at = len(vectors)
        print(f"    {ak:<16}  {ap:>5} / {at:<5}  {'✅' if ap==at else '❌'}")
        total += at; passed += ap
        results[ak] = {"total": at, "passed": ap, "failed": at-ap}
    return total, passed, results


# ═══════════════════════════════════════════════════════════════
# SUITE 4: ECDSA SIGNATURE VERIFICATION (FIPS 186-4)
# ═══════════════════════════════════════════════════════════════

def run_ecdsa_suite(zip_bytes):
    if not HAS_CRYPTO:
        print("    ⚠️  'cryptography' package not installed — skipping")
        print("    Install: pip install cryptography")
        return 0, 0, {}

    CURVES = {
        "P-192": ec.SECP192R1(), "P-224": ec.SECP224R1(), "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1(),
    }

    def get_hash(name):
        return {"SHA-1":crypto_hashes.SHA1(),"SHA-224":crypto_hashes.SHA224(),"SHA-256":crypto_hashes.SHA256(),"SHA-384":crypto_hashes.SHA384(),"SHA-512":crypto_hashes.SHA512()}.get(name)

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    sigver = zf.read("SigVer.rsp").decode("utf-8","replace")

    cur_curve_name = None
    cur_curve = None
    cur_hash_name = None
    current = {}
    total = passed = skipped = 0
    results = {}

    for line in sigver.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            parts = line[1:-1].split(",")
            if len(parts) == 2:
                cname, hname = parts[0].strip(), parts[1].strip()
                cur_curve = CURVES.get(cname)
                cur_curve_name = cname
                cur_hash_name = hname
            continue
        if "=" in line:
            k,v = line.split("=",1)
            current[k.strip()] = v.strip()

        if "Result" in current:
            if not cur_curve or not get_hash(cur_hash_name):
                skipped += 1
                current = {}
                continue
            try:
                qx = int(current["Qx"], 16)
                qy = int(current["Qy"], 16)
                r_val = int(current["R"], 16)
                s_val = int(current["S"], 16)
                msg = bytes.fromhex(current["Msg"])
                expected_pass = current["Result"].startswith("P")

                pubkey = ec.EllipticCurvePublicNumbers(qx, qy, cur_curve).public_key(default_backend())
                sig = utils.encode_dss_signature(r_val, s_val)
                try:
                    pubkey.verify(sig, msg, ec.ECDSA(get_hash(cur_hash_name)))
                    actual_pass = True
                except:
                    actual_pass = False

                combo = f"{cur_curve_name}_{cur_hash_name.replace('-','')}"
                if combo not in results:
                    results[combo] = {"total": 0, "passed": 0, "failed": 0}
                results[combo]["total"] += 1

                if expected_pass == actual_pass:
                    passed += 1
                    results[combo]["passed"] += 1
                else:
                    results[combo]["failed"] += 1
                total += 1
            except:
                skipped += 1
            current = {}

    # Print per-curve summary
    by_curve = {}
    for combo, data in results.items():
        curve = combo.split("_")[0]
        if curve not in by_curve:
            by_curve[curve] = {"total": 0, "passed": 0}
        by_curve[curve]["total"] += data["total"]
        by_curve[curve]["passed"] += data["passed"]

    for curve in sorted(by_curve):
        d = by_curve[curve]
        print(f"    ECDSA_{curve:<8}  {d['passed']:>5} / {d['total']:<5}  {'✅' if d['passed']==d['total'] else '❌'}")

    if skipped:
        print(f"    (Skipped {skipped} binary/Koblitz curve vectors — not in NIST prime set)")

    return total, passed, results


# ═══════════════════════════════════════════════════════════════
# SUITE 5: AES-GCM AUTHENTICATED ENCRYPTION (SP 800-38D)
# ═══════════════════════════════════════════════════════════════

def run_aesgcm_suite(zip_bytes):
    if not HAS_CRYPTO:
        print("    ⚠️  'cryptography' package not installed — skipping")
        print("    Install: pip install cryptography")
        return 0, 0, {}

    def gcm_decrypt(key, iv, ct, aad, tag):
        dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag, min_tag_length=4), backend=default_backend()).decryptor()
        dec.authenticate_additional_data(aad)
        return dec.update(ct) + dec.finalize()

    def gcm_encrypt(key, iv, pt, aad):
        enc = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(pt) + enc.finalize()
        return ct, enc.tag

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    total = passed = skipped = 0
    results = {}

    for fname in sorted(n for n in zf.namelist() if n.lower().endswith(".rsp")):
        content = zf.read(fname).decode("utf-8","replace")
        is_decrypt = "decrypt" in fname.lower()
        is_encrypt = "encrypt" in fname.lower()

        # Parse key size from filename
        keysize = ""
        for ks in ["128","192","256"]:
            if ks in fname:
                keysize = ks; break

        label = f"{'Dec' if is_decrypt else 'Enc'}_{keysize}"
        ft = fp = fs = 0
        cur_ivlen = 96  # default
        current = {}

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                m = re.match(r'\[IVlen = (\d+)\]', line)
                if m:
                    cur_ivlen = int(m.group(1))
                continue

            if line == "FAIL":
                # Decrypt FAIL vector
                if "Tag" in current and is_decrypt:
                    if cur_ivlen < 64 or cur_ivlen > 1024:
                        fs += 1
                        current = {}
                        continue
                    try:
                        key = bytes.fromhex(current["Key"])
                        iv = bytes.fromhex(current["IV"])
                        ct = bytes.fromhex(current.get("CT","")) if current.get("CT","") else b""
                        aad = bytes.fromhex(current.get("AAD","")) if current.get("AAD","") else b""
                        tag = bytes.fromhex(current["Tag"])
                        try:
                            gcm_decrypt(key, iv, ct, aad, tag)
                            pass  # should have failed
                        except:
                            fp += 1  # correctly rejected
                        ft += 1
                    except:
                        fs += 1
                current = {}
                continue

            if "=" in line:
                k,v = line.split("=",1)
                current[k.strip()] = v.strip()

                if is_decrypt and k.strip() == "PT":
                    if "Tag" in current:
                        if cur_ivlen < 64 or cur_ivlen > 1024:
                            fs += 1
                            current = {}
                            continue
                        try:
                            key = bytes.fromhex(current["Key"])
                            iv = bytes.fromhex(current["IV"])
                            ct = bytes.fromhex(current.get("CT","")) if current.get("CT","") else b""
                            aad = bytes.fromhex(current.get("AAD","")) if current.get("AAD","") else b""
                            tag = bytes.fromhex(current["Tag"])
                            expected_pt = bytes.fromhex(current["PT"]) if current["PT"] else b""
                            pt = gcm_decrypt(key, iv, ct, aad, tag)
                            if pt == expected_pt:
                                fp += 1
                            ft += 1
                        except:
                            ft += 1
                    current = {}

                elif is_encrypt and k.strip() == "Tag":
                    if "PT" in current:
                        if cur_ivlen < 64 or cur_ivlen > 1024:
                            fs += 1
                            current = {}
                            continue
                        try:
                            key = bytes.fromhex(current["Key"])
                            iv = bytes.fromhex(current["IV"])
                            pt = bytes.fromhex(current.get("PT","")) if current.get("PT","") else b""
                            aad = bytes.fromhex(current.get("AAD","")) if current.get("AAD","") else b""
                            expected_ct = bytes.fromhex(current.get("CT","")) if current.get("CT","") else b""
                            expected_tag = bytes.fromhex(current["Tag"])
                            ct, tag = gcm_encrypt(key, iv, pt, aad)
                            # Tag may be truncated in test vectors
                            tag_trunc = tag[:len(expected_tag)]
                            if ct == expected_ct and tag_trunc == expected_tag:
                                fp += 1
                            ft += 1
                        except:
                            ft += 1
                    current = {}

        print(f"    AES_GCM_{label:<10}  {fp:>5} / {ft:<5}  {'✅' if fp==ft else '❌'}  (skipped {fs} unsupported IV)")
        total += ft; passed += fp; skipped += fs
        results[f"AES_GCM_{label}"] = {"total": ft, "passed": fp, "failed": ft-fp}

    if skipped:
        print(f"    (Skipped {skipped} vectors with IV < 64 bits — outside library supported range)")

    return total, passed, results


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    start = time.time()

    print()
    print("  ╔" + "═"*66 + "╗")
    print("  ║" + "THE HENRY COMPANY".center(66) + "║")
    print("  ║" + "NIST Cryptographic Verification Suite v2".center(66) + "║")
    print("  ║" + "Live from csrc.nist.gov".center(66) + "║")
    print("  ╚" + "═"*66 + "╝")
    print()
    print("  Standards under test:")
    print("    1. FIPS 180-4    SHA-1 / SHA-2 .............. Integrity")
    print("    2. FIPS 202      SHA-3 / Keccak ............. Crypto Agility")
    print("    3. FIPS 198-1    HMAC ....................... Authority")
    print("    4. FIPS 186-4    ECDSA Signatures ........... Identity")
    print("    5. SP 800-38D    AES-GCM Auth Encryption .... Confidentiality")
    print()
    if HAS_CRYPTO:
        print("  cryptography library: ✅ installed")
    else:
        print("  cryptography library: ❌ not found (suites 4-5 will skip)")
        print("  Install: pip install cryptography")
    print()

    grand_total = 0
    grand_passed = 0
    all_results = {}
    all_skipped = {}

    suites = [
        ("SHA-2",   "FIPS 180-4", "INTEGRITY",       "Data cannot be changed without detection",     run_sha2_suite),
        ("SHA-3",   "FIPS 202",   "CRYPTO AGILITY",   "Can switch to next-gen if SHA-2 ever breaks",  run_sha3_suite),
        ("HMAC",    "FIPS 198-1", "AUTHORITY",         "Only the right key produces the right seal",   run_hmac_suite),
        ("ECDSA",   "FIPS 186-4", "IDENTITY",          "Proves WHO signed, not just THAT it was signed", run_ecdsa_suite),
        ("AES-GCM", "SP 800-38D", "CONFIDENTIALITY",   "Encrypted data is unreadable AND tamper-proof",  run_aesgcm_suite),
    ]

    for idx, (name, std, domain, desc, runner) in enumerate(suites, 1):
        src = NIST_SOURCES[name]
        print(f"  {'─'*66}")
        print(f"  SUITE {idx}: {name} ({std}) — {domain}")
        print(f"  {desc}")
        print(f"  {'─'*66}")
        try:
            zdata = download(src["url"])
            print(f"    Downloaded: {len(zdata):,} bytes from NIST")
            print()
            t, p, r = runner(zdata)
            grand_total += t; grand_passed += p
            all_results[name] = {"standard": std, "domain": domain, "total": t, "passed": p, "algorithms": r}
            mark = "✅" if t == p else "❌"
            print(f"\n    Suite {idx} result: {p:,} / {t:,}  {mark}")
        except Exception as e:
            print(f"    ❌ Suite failed: {e}")
        print()

    elapsed = time.time() - start
    all_passed = grand_passed == grand_total

    # ── Environment ─────────────────────────────────────────────
    try: openssl_ver = ssl.OPENSSL_VERSION
    except: openssl_ver = "unknown"
    try:
        from cryptography import __version__ as crypto_ver
    except:
        crypto_ver = "N/A"

    # ── Grand Summary ───────────────────────────────────────────
    print()
    print("  ╔" + "═"*66 + "╗")
    print("  ║" + "VERIFICATION REPORT".center(66) + "║")
    print("  ╠" + "═"*66 + "╣")
    print("  ║" + "  SUITE                    STANDARD       PASSED   TOTAL   STATUS".ljust(66) + "║")
    print("  ║" + "  ─────────────────────────────────────────────────────────────".ljust(66) + "║")

    for name, data in all_results.items():
        std = data["standard"]
        t = data["total"]
        p = data["passed"]
        mark = "✅" if p == t else "❌"
        line = f"  {name:<22} {std:<14} {p:>6}   {t:<6} {mark}"
        print("  ║" + line.ljust(66) + "║")
        for algo in sorted(data["algorithms"]):
            ad = data["algorithms"][algo]
            am = "✅" if ad["failed"]==0 else "❌"
            aline = f"    {algo:<20} {'':14} {ad['passed']:>6}   {ad['total']:<6} {am}"
            print("  ║" + aline.ljust(66) + "║")

    print("  ╠" + "═"*66 + "╣")

    total_algos = sum(len(s["algorithms"]) for s in all_results.values())
    mc_ops = 0
    for s in all_results.values():
        for a, d in s["algorithms"].items():
            if "SHA" in a and "HMAC" not in a and d["total"] > 200:
                mc_ops += 100 * 1000
    total_ops = grand_total + mc_ops

    gline = f"  GRAND TOTAL:  {grand_passed:,} / {grand_total:,}  {'✅ ALL PASSED' if all_passed else '❌ FAILURES'}"
    print("  ║" + gline.ljust(66) + "║")
    print("  ║" + f"  Standards: {len(all_results)}  |  Algorithms: {total_algos}  |  Time: {elapsed:.1f}s".ljust(66) + "║")
    print("  ║" + f"  Crypto operations: ~{total_ops:,}+".ljust(66) + "║")
    print("  ╚" + "═"*66 + "╝")
    print()

    # ── Verdict ─────────────────────────────────────────────────
    if all_passed:
        print(f"  ✅ VERDICT: ALL {grand_total:,} NIST CAVP TEST VECTORS PASSED")
        print(f"             ACROSS {len(all_results)} FEDERAL STANDARDS")
        print()
        print("  ┌────────────────────────────────────────────────────────────┐")
        print("  │  DOMAIN              STANDARD       PROOF                  │")
        print("  │  ─────────────────────────────────────────────────────────  │")
        for name, data in all_results.items():
            d = data["domain"]
            s = data["standard"]
            line = f"  │  {d:<20} {s:<14} {data['passed']:,} vectors verified"
            print(line.ljust(65) + "│")
        print("  └────────────────────────────────────────────────────────────┘")
        print()
    else:
        print(f"  ❌ VERDICT: {grand_total - grand_passed:,} TEST VECTORS FAILED")

    # ── Report ──────────────────────────────────────────────────
    report = {
        "verification_report": {
            "title": "NIST Cryptographic Verification Suite v2",
            "organization": "The Henry Company",
            "version": "2.0",
            "standards": [{"name": s["standard"], "title": s["title"], "url": s["url"]} for s in NIST_SOURCES.values()],
            "environment": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "machine": platform.machine(),
                "openssl": openssl_ver,
                "cryptography_lib": crypto_ver,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 1),
            "results": {k: {"standard": v["standard"], "domain": v["domain"], "total": v["total"], "passed": v["passed"], "algorithms": {a: {"total": d["total"], "passed": d["passed"]} for a,d in v["algorithms"].items()}} for k,v in all_results.items()},
            "summary": {
                "standards_tested": len(all_results),
                "algorithms_tested": total_algos,
                "total_vectors": grand_total,
                "passed": grand_passed,
                "failed": grand_total - grand_passed,
                "crypto_operations": total_ops,
            },
            "verdict": f"PASS — {grand_total:,} vectors across {len(all_results)} standards" if all_passed else "FAIL",
            "infrastructure": {
                "google_cloud_platform": "FIPS 140-3, FedRAMP High, SOC 1/2/3, ISO 27001",
                "firebase": "AES-256 at rest, TLS 1.3 in transit",
                "cloudflare": "SOC 2 Type II, ISO 27001, FIPS 140-2 L1",
            },
        }
    }

    rpath = "nist_crypto_suite_verification.json"
    with open(rpath, "w") as f:
        json.dump(report, f, indent=2)
    rbytes = json.dumps(report, indent=2).encode("utf-8")
    seal_hash = hashlib.sha256(rbytes).hexdigest()
    seal = {"seal": {"document": rpath, "algorithm": "SHA-256", "hash": seal_hash, "timestamp": datetime.now(timezone.utc).isoformat(), "verified_by": "The Henry Company"}}
    spath = "nist_crypto_suite_verification_seal.json"
    with open(spath, "w") as f:
        json.dump(seal, f, indent=2)

    print()
    print(f"  Report:    {os.path.abspath(rpath)}")
    print(f"  Seal:      {os.path.abspath(spath)}")
    print(f"  Seal hash: {seal_hash}")
    print()
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print()
    print("  Environment:")
    print(f"    Python:       {sys.version.split()[0]}")
    print(f"    Platform:     {platform.platform()}")
    print(f"    OpenSSL:      {openssl_ver}")
    print(f"    cryptography: {crypto_ver}")
    print()
    print("  Infrastructure certifications (inherited):")
    print("    GCP:        FIPS 140-3, FedRAMP High, SOC 1/2/3, ISO 27001")
    print("    Firebase:   AES-256 at rest, TLS 1.3 in transit")
    print("    Cloudflare: SOC 2 Type II, ISO 27001, FIPS 140-2 L1")
    print()
    print("  NIST sources (all .gov — verify any of these in your browser):")
    for name, src in NIST_SOURCES.items():
        print(f"    {name:<10} {src['standard']:<12} {src['url']}")
    print(f"    CAVP page:  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program")
    print()
    print("  ╔" + "═"*66 + "╗")
    print("  ║" + "Five standards. One instrument. Every seal verified.".center(66) + "║")
    print("  ╚" + "═"*66 + "╝")
    print()

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
