from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

key = b'0123456789abcdef0123456789abcdef'  # 32 bytes = AES-256
iv = get_random_bytes(16)

with open("calc64_v3.bin", "rb") as f:
    data = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, AES.block_size))

with open("encrypted-result.bin", "wb") as f:
    f.write(iv + ciphertext)

print("Encryption success. Check encrypted-result.bin")