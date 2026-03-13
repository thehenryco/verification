# Cryptographic Verification Suite v6

**The Henry Company** publishes this script so anyone can verify our cryptographic foundation.

**Run it yourself. Check our work.**

---

## Latest Results
```
366,344 / 366,344 — ALL PASSED
42 suites · 175 algorithms · 12 layers · Zero failures
```

## Run It Yourself
```
pip install cryptography
python nist_crypto_suite.py
```

Downloads all vectors live from csrc.nist.gov and github.com/google/wycheproof. Nothing hardcoded. Every run produces a sealed report and Merkle-tree evidence package.

## 12 Verification Layers

| Layer | Source | Tests |
|-------|--------|-------|
| 1. NIST CAVP | csrc.nist.gov | 55,064 |
| 2. Wycheproof | Google | 20,262 |
| 3. Differential | Cross-engine | 30,000 |
| 4. Fuzz | Roundtrip | 40,000 |
| 5. Stress | Sustained load | 200,000 |
| 6. Timing | Side-channel | 4 |
| 7. RNG | SP 800-22 | 6 |
| 8. Negative | Corrupt/reject | 12,000 |
| 9. Interop | Cross-library | 8,000 |
| 10. Policy | Config audit | 7 |
| 11. Evidence | Merkle seal | 1 |
| 12. Mutation | Tamper proof | 1,000 |

## NIST Standards Covered

FIPS 180-4 · FIPS 202 · FIPS 198-1 · FIPS 186-4 · FIPS 197 · SP 800-38B · SP 800-38C · SP 800-38D · SP 800-56A

## What This Is Not

This is a pre-validation verification harness, not a FIPS 140-3 certification. Official certification requires accredited laboratory testing through the NVLAP program.

---

**The Henry Company** — thehenrycompany.com
