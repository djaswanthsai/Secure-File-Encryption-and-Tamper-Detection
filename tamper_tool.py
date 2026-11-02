#!/usr/bin/env python3
"""
Tamper Tool: Simulates an active adversary flipping bits or modifying tags.
"""

import os
import argparse


def tamper_file(file_path: str, offset: int = 40, flip_bit: bool = True, corrupt_tag: bool = False):
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    if corrupt_tag:
        # Tag is located at byte offsets 16 to 31
        data[16:32] = os.urandom(16)
        print(" [*] Corrupted 16-byte authentication tag at offsets 16-31 with random bytes.")
    elif flip_bit:
        if offset >= len(data):
            raise IndexError(f"Offset {offset} is out of file bounds ({len(data)} bytes).")
        # Flip least-significant bit
        data[offset] ^= 0x01
        print(f" [*] Bit flipped at offset {offset}. File modified.")

    with open(file_path, "wb") as f:
        f.write(data)


def main():
    parser = argparse.ArgumentParser(description="Simulate byte-level file tampering.")
    parser.add_argument("--file", required=True, help="Target binary file")
    parser.add_argument("--byte", type=int, default=40, help="Byte offset to flip (default: 40)")
    parser.add_argument("--flip", action="store_true", help="Flip LSB at specified byte offset")
    parser.add_argument("--corrupt-tag", action="store_true", help="Replace 16B tag with random bytes")

    args = parser.parse_args()
    tamper_file(args.file, args.byte, args.flip, args.corrupt_tag)


if __name__ == "__main__":
    main()