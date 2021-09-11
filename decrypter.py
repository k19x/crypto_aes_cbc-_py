from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

enc = input("Insert: ")

BLOCK_SIZE = 32
key = b'1234567812345678'
mode = AES.MODE_CBC
iv = b'1234567812345678'

# Decryption
decryption_suite = AES.new(key, mode, iv)
dec = base64.b64decode(enc)
plain_text = unpad(decryption_suite.decrypt(dec), BLOCK_SIZE).decode('utf-8')
print("DECRYPTED_DATA: ",plain_text)