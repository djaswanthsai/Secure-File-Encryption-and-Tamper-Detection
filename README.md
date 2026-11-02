# Secure-File-Encryption-and-Tamper-Detection

A Python cryptographic security suite implementing authenticated encryption to ensure data confidentiality, integrity, and tamper detection. The system detects bit-level modifications and tag corruptions in encrypted payloads before decryption occurs.

---

## Features

- **Authenticated Encryption:** Guarantees both data privacy and payload authenticity.
- **Tamper Detection:** Detects single-bit alterations, truncated files, or forged authentication tags.
- **Adversarial Simulation:** Includes utilities to simulate active byte/bit corruption attacks on ciphertext.
- **Automated Security Verification:** Test harness to validate cryptographic guarantees against tampering.

---

## Project Structure

```text
├── aegisvault.py           # Core cryptographic engine (encryption & decryption)
├── tamper_tool.py          # Adversarial utility for bit-flipping and tag corruption
├── test_security_suite.py  # Test runner validating tamper detection behaviors
└── README.md               # Project documentation
