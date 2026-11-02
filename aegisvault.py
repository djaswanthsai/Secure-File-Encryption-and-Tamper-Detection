#!/usr/bin/env python3
"""
AegisVault: Secure File Encryption & Tamper Detection Engine
Standard: NIST SP 800-38D (AES-256-GCM)
Binary Envelope:
    [ Magic: 4B ] [ Nonce: 12B ] [ Tag: 16B ] [ Ciphertext: N Bytes ]
"""

import os
import sys
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC_HEADER = b"AEGS"  # 0x41 0x45 0x47 0x53
HEADER_SIZE = 32        # 4B Magic + 12B Nonce + 16B Tag


def generate_key() -> bytes:
    """Generate a 256-bit (32-byte) key using the OS CSPRNG."""
    return os.urandom(32)


def encrypt_file(input_path: str, output_path: str, key: bytes = None) -> bytes:
    """
    Encrypts a file with AES-256-GCM and packages it into the AegisVault binary format.
    Returns the 256-bit key used.
    """
    if key is None:
        key = generate_key()
    elif len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (256 bits).")

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Generate fresh 96-bit (12-byte) nonce via CSPRNG
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    # Encrypt: AESGCM produces (ciphertext + 16-byte tag)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    # Construct binary envelope: Magic(4B) + Nonce(12B) + Tag(16B) + Ciphertext(NB)
    payload = MAGIC_HEADER + nonce + tag + ciphertext

    with open(output_path, "wb") as f:
        f.write(payload)

    return key


def decrypt_file(input_path: str, output_path: str, key: bytes) -> bool:
    """
    Validates binary header, verifies 128-bit GHASH tag, and decrypts ciphertext.
    Enforces strict fail-closed behavior: 0 bytes written to disk if validation fails.
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (256 bits).")

    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) < HEADER_SIZE:
        print("[CRITICAL] File corrupted: payload smaller than 32-byte header.")
        return False

    # Header parsing
    magic = data[0:4]
    nonce = data[4:16]
    tag = data[16:32]
    ciphertext = data[32:]

    if magic != MAGIC_HEADER:
        print(f"[CRITICAL] Invalid file format. Expected header '{MAGIC_HEADER.decode()}', got {magic}.")
        return False

    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag

    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
    except InvalidTag:
        print("[CRITICAL] Authentication Tag verification failed!")
        print("[SECURITY ERROR] File tampering, tag alteration, or wrong key detected.")
        print(" [!] Decryption aborted. Zero bytes released to disk.")
        return False

    # Atomic write: Only release bytes after successful tag verification
    with open(output_path, "wb") as f:
        f.write(plaintext)

    return True


def main():
    parser = argparse.ArgumentParser(description="AegisVault Secure Storage CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt CLI
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt file")
    enc_parser.add_argument("file", help="Input plaintext file")
    enc_parser.add_argument("--out", required=True, help="Output .enc file")
    enc_parser.add_argument("--key", help="Hex string of 256-bit key (optional)")

    # Decrypt CLI
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt file")
    dec_parser.add_argument("file", help="Input .enc file")
    dec_parser.add_argument("--out", required=True, help="Output plaintext file")
    dec_parser.add_argument("--key", required=True, help="Hex string of 256-bit key")

    args = parser.parse_args()

    if args.command == "encrypt":
        key = bytes.fromhex(args.key) if args.key else None
        used_key = encrypt_file(args.file, args.out, key)
        print(f" [+] Generated/Used 256-bit Key: {used_key.hex()}")
        print(f" [+] Encrypted {os.path.getsize(args.file)} bytes -> {args.out} written successfully.")

    elif args.command == "decrypt":
        key = bytes.fromhex(args.key)
        success = decrypt_file(args.file, args.out, key)
        if success:
            print(f" [+] Decryption successful -> {args.out} verified and written.")
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()