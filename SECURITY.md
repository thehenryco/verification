# Security Policy

## Scope

This repository contains a verification script that downloads test vectors from NIST and validates cryptographic implementations. It does not contain The Henry Company's proprietary platform, algorithms, or operational intelligence system.

## Reporting a Vulnerability

Email: jerod.harbor@thehenrycompany.com

Subject line: [SECURITY] verification — brief description

We will acknowledge receipt within 48 hours.

## What This Script Does

- Downloads test vector archives from csrc.nist.gov (HTTPS only)
- Runs cryptographic operations using Python standard library and the cryptography package
- Compares results to NIST published expected values
- Writes a JSON report to the local filesystem

## What This Script Does NOT Do

- Access any private systems or APIs
- Transmit any data to any third party
- Expose any proprietary Henry Company technology
