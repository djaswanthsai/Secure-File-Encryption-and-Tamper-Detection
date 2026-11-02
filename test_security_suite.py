#!/usr/bin/env python3
"""
Comprehensive Automated Test Suite for AegisVault
Covers: CSPRNG Entropy, Correctness, Tampering, Wrong Key, and Magic Byte checks.
Run with: pytest -v test_security_suite.py
"""

import os
import hashlib
import pytest
from aegisvault import encrypt_file, decrypt_file, generate_key, MAGIC_HEADER
from tamper_tool import tamper_file


@pytest.fixture
def sample_file(tmp_path):
    p = tmp_path / "test_data.txt"
    p.write_bytes(b"AegisVault Confidential Document: Cryptographic Grade Verification = 100%")
    return str(p)


# Module 1: Keygen & CSPRNG (test_keygen.py)
class TestKeygen:
    def test_key_length(self):
        key = generate_key()
        assert len(key) == 32

    def test_key_uniqueness(self):
        k1 = generate_key()
        k2 = generate_key()
        assert k1 != k2


# Module 2: Correctness & SHA-256 Round-Trip (test_roundtrip.py)
class TestRoundTrip:
    def test_exact_hash_match(self, sample_file, tmp_path):
        enc_file = str(tmp_path / "data.enc")
        dec_file = str(tmp_path / "recovered.txt")

        key = encrypt_file(sample_file, enc_file)
        success = decrypt_file(enc_file, dec_file, key)

        assert success is True
        assert os.path.exists(dec_file)

        # Bit-for-bit identity verification using SHA-256
        with open(sample_file, "rb") as f1, open(dec_file, "rb") as f2:
            assert hashlib.sha256(f1.read()).hexdigest() == hashlib.sha256(f2.read()).hexdigest()

    def test_header_magic_intact(self, sample_file, tmp_path):
        enc_file = str(tmp_path / "data.enc")
        encrypt_file(sample_file, enc_file)
        with open(enc_file, "rb") as f:
            assert f.read(4) == MAGIC_HEADER


# Module 3: Tamper Detection (test_tamper.py)
class TestTamperDetection:
    def test_ciphertext_single_bit_flip(self, sample_file, tmp_path):
        """Experiment 1: Bit flip at offset 40 (inside ciphertext payload)."""
        enc_file = str(tmp_path / "tamper_ct.enc")
        dec_file = str(tmp_path / "tamper_ct.txt")

        key = encrypt_file(sample_file, enc_file)
        tamper_file(enc_file, offset=40, flip_bit=True)

        success = decrypt_file(enc_file, dec_file, key)
        assert success is False
        assert not os.path.exists(dec_file)  # Fail-closed guarantee

    def test_auth_tag_corruption(self, sample_file, tmp_path):
        """Experiment 2: Alter 16-byte authentication tag."""
        enc_file = str(tmp_path / "tamper_tag.enc")
        dec_file = str(tmp_path / "tamper_tag.txt")

        key = encrypt_file(sample_file, enc_file)
        tamper_file(enc_file, offset=16, corrupt_tag=True)

        success = decrypt_file(enc_file, dec_file, key)
        assert success is False
        assert not os.path.exists(dec_file)


# Module 4: Wrong-Key Attack Defense (test_wrong_key.py)
class TestWrongKeyAttack:
    def test_incorrect_key_rejection(self, sample_file, tmp_path):
        """Experiment 3: Attempt decryption with an incorrect 256-bit key."""
        enc_file = str(tmp_path / "secure.enc")
        dec_file = str(tmp_path / "wrong_key.txt")

        valid_key = encrypt_file(sample_file, enc_file)
        wrong_key = generate_key()

        assert valid_key != wrong_key
        success = decrypt_file(enc_file, dec_file, wrong_key)

        assert success is False
        assert not os.path.exists(dec_file)