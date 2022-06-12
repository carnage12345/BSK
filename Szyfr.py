import hashlib
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import rsa

(publicKey, privateKey) = rsa.newkeys(1024)

class AESCipher:
    def __init__(self):
        password = 'lolo'
        self.local_key = hashlib.md5(password.encode('utf8')).digest()
        self.cipher = 'nothing'

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.local_key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.local_key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


with open('publicKeyA.pem', 'wb') as f:
    f.write(publicKey.save_pkcs1())

with open('publicKeyA.pem', 'rb') as f:
    publicKey = f.read()

print(publicKey)
cbc = AESCipher()
encryptedPublicKey = cbc.encrypt(str(publicKey))
with open('publicKeyA.pem', 'rb') as f:
    f.write()


