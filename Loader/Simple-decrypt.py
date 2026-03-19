from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b'0123456789abcdef0123456789abcdef'

with open("encrypted.bin", "rb") as f:
    iv = f.read(16)
    ciphertext = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

with open("decrypted-results.bin", "wb") as f:
    f.write(plaintext)

print("Decrypt success. Check decrypted-results.bin ")