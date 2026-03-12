# NIST Cryptographic Verification Suite

**The Henry Company** publishes this script so anyone can verify our cryptographic foundation.

**Run it yourself. Check our work.**

---

## Latest Results

36,111 / 36,111 NIST CAVP test vectors passed. 45 algorithms. 5 federal standards. 0 failures.

| Domain | Suite | Standard | Vectors | Status |
|--------|-------|----------|---------|--------|
| Integrity | SHA-2 | FIPS 180-4 | 1,401 | Passed |
| Crypto Agility | SHA-3 | FIPS 202 | 1,260 | Passed |
| Authority | HMAC | FIPS 198-1 | 1,575 | Passed |
| Identity | ECDSA | FIPS 186-4 | 375 | Passed |
| Confidentiality | AES-GCM | SP 800-38D | 31,500 | Passed |
| **Total** | **5 suites** | **5 standards** | **36,111** | **All passed** |

---

## Run It Yourself

Suites 1-3 need only Python 3. Suites 4-5 need one package:

    pip install cryptography
    python nist_crypto_suite.py

The script downloads 5 test vector archives from csrc.nist.gov, runs every vector, and generates a sealed verification report.

---

## NIST Sources

Every test vector is downloaded live from the US government. Nothing is hardcoded.

| Suite | Standard | Source |
|-------|----------|--------|
| SHA-2 | FIPS 180-4 | [shabytetestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip) |
| SHA-3 | FIPS 202 | [sha-3bytetestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip) |
| HMAC | FIPS 198-1 | [hmactestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip) |
| ECDSA | FIPS 186-4 | [186-3ecdsatestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3ecdsatestvectors.zip) |
| AES-GCM | SP 800-38D | [gcmtestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip) |

NIST CAVP Program: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

---

## Infrastructure

| Provider | Certifications |
|----------|---------------|
| Google Cloud Platform | FIPS 140-3 (BoringCrypto), FedRAMP High, SOC 1/2/3, ISO 27001 |
| Firebase | AES-256 at rest, TLS 1.3 in transit (inherits GCP) |
| Cloudflare | SOC 2 Type II, ISO 27001, FIPS 140-2 Level 1 |

---

## Why We Publish This

Most companies say they are secure. We show our work.

This script tests our cryptographic sealing mechanism. It does not expose our proprietary instrument, algorithms, or analytical methods. It proves the lock works.

If you find an issue, open an issue.

---

## About

The Henry Company reads your existing ERP data and shows you where value disappears — dollar amounts, specific handoffs, verified. Not estimated.

[thehenrycompany.com](https://thehenrycompany.com) | [thehenrycompany.com/verify](https://thehenrycompany.com/verify) | jerod.harbor@thehenrycompany.com

---

## License

MIT — The verification script is free. The instrument is not.
