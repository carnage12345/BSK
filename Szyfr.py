import hashlib
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import rsa

(publicKey, privateKey) = rsa.newkeys(1024)
print(publicKey.__class__)
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


publicKeyBytes = publicKey.save_pkcs1()

print('bajtowy klucz publiczny: ', publicKeyBytes)
# print(publicKey.__class__)

publicKeyBytesUTF8 = publicKeyBytes.decode('utf-8')
# print(publicKeyBytesUTF8 )
cbc = AESCipher()
encryptedPublicKey = cbc.encrypt(publicKeyBytesUTF8)
# print(encryptedPublicKey)

with open('encryptedA.txt', 'wb') as f:
    f.write(encryptedPublicKey)

with open('encryptedA.txt', 'rb') as f:
    output = f.read().decode('utf-8')

# print(output)

decryptedPublicKey = cbc.decrypt(output)
# decryptedPublicKey = cbc.decrypt(encryptedPublicKey)

print('Odszyfrowany klucz publiczny: ', decryptedPublicKey)


ready_key = rsa.PublicKey.load_pkcs1(decryptedPublicKey)
print(ready_key.__class__)
# with open('./Keys' + letter + '/PublicKeys/encryptedPublicKey' + letter + '.pem', 'w') as f:
#     f.write(cipheredPublicKey)
#     # f.write(cipheredPublicKey.save_pkcs1('PEM'))
# with open('./Keys' + letter + '/PrivateKeys/encryptedPrivateKey' + letter + '.pem', 'w') as f:
#     f.write(cipheredPrivateKey)
#     # f.write(cipheredPrivateKey.save_pkcs1('PEM'))
