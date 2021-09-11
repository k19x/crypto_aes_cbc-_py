from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

text = input("Insert: ")

BLOCK_SIZE = 32
key = b'1234567812345678'
mode = AES.MODE_CBC
iv = b'1234567812345678'
# Encryption

encryption_suite = AES.new(key, mode, iv)
cipher_text = encryption_suite.encrypt(pad(str(text).encode('utf-8'), BLOCK_SIZE))
enc = base64.b64encode(cipher_text).decode('utf-8')
print("ENCRYPTED_DATA: ", enc)
