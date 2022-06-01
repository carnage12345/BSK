#!/usr/bin/env python3
#
# This is a simple script to encrypt a message using AES
# with CBC mode in Python 3.
# Before running it, you must install pycryptodome:
#
# $ python -m pip install PyCryptodome
#
# Author.: José Lopes
# Date...: 2019-06-14
# License: MIT
##

import hashlib
import rsa
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def load_keys():
    with open('../KeysA/publicKeyA.pem', 'rb') as f:
        publicKeyA = rsa.PublicKey.load_pkcs1(f.read())
    with open('../KeysA/privateKeyA.pem', 'rb') as f:
        privateKeyA = rsa.PrivateKey.load_pkcs1(f.read())
    with open('../KeysB/publicKeyB.pem', 'rb') as f:
        publicKeyB = rsa.PublicKey.load_pkcs1(f.read())
    with open('../KeysB/privateKeyB.pem', 'rb') as f:
        privateKeyB = rsa.PrivateKey.load_pkcs1(f.read())

    return publicKeyA, privateKeyA, publicKeyB, privateKeyB


def load_ecnrypted_keys():
    with open('../KeysA/encryptedPublicKeyA.txt', 'r') as f:
        cipherPublicA = f.read()
    with open('../KeysA/encryptedPrivateKeyA.txt', 'r') as f:
        cipherPrivateA = f.read()
    with open('../KeysB/encryptedPublicKeyB.txt', 'r') as f:
        cipherPublicB = f.read()
    with open('../KeysB/encryptedPrivateKeyB.txt', 'r') as f:
        cipherPrivateB = f.read()

    return cipherPublicA, cipherPrivateA, cipherPublicB, cipherPrivateB


class AESCipher:
    def __init__(self):
        password = input('Input user-friendly password : ')
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


def encryptRSAKeysAndSave():
    publicA, privateA, publicB, privateB = load_keys()

    cbc = AESCipher()

    cipherPublicA = cbc.encrypt(str(publicA)).decode('utf-8')
    cipherPrivateA = cbc.encrypt(str(privateA)).decode('utf-8')
    cipherPublicB = cbc.encrypt(str(publicB)).decode('utf-8')
    cipherPrivateB = cbc.encrypt(str(privateB)).decode('utf-8')

    with open('../KeysA/encryptedPublicKeyA.txt', 'w') as f:
        f.write(cipherPublicA)
    with open('../KeysA/encryptedPrivateKeyA.txt', 'w') as f:
        f.write(cipherPrivateA)
    with open('../KeysB/encryptedPublicKeyB.txt', 'w') as f:
        f.write(cipherPublicB)
    with open('../KeysB/encryptedPrivateKeyB.txt', 'w') as f:
        f.write(cipherPrivateB)


def decryptRSAKeysAndReturn():
    cipherPublicA, cipherPrivateA, cipherPublicB, cipherPrivateB = load_ecnrypted_keys()

    cbc = AESCipher()

    publicA = cbc.decrypt(str(cipherPublicA)).decode('utf-8')
    privateA = cbc.decrypt(cipherPrivateA).decode('utf-8')
    publicB = cbc.decrypt(cipherPublicB).decode('utf-8')
    privateB = cbc.decrypt(cipherPrivateB).decode('utf-8')

    return publicA, privateA, publicB, privateB


print("Plain text keys: ")
v = load_keys()
for x in v:
    print(x)
print()

encryptRSAKeysAndSave()
print("Encrypted keys: ")
z = load_ecnrypted_keys()
for x in z:
    print(x)
print()


print("Decrypted keys: ")
y = decryptRSAKeysAndReturn()
for x in y:
    print(x)
print()
