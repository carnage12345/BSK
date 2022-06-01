import socket  # Sockets do późniejszego użycia https://www.geeksforgeeks.org/socket-programming-python/
import tkinter
from tkinter import filedialog
import rsa
import tqdm  # do fancy progress bars 'ów
import time
import os  # co to jest???
import hashlib
import rsa
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

#  RSA key functions
def generate_keys():
    (publicKey, privateKey) = rsa.newkeys(1024)  # 1024 - 128 byte key
    with open('KeysA/publicKeyA.pem', 'wb') as f:
        f.write(publicKey.save_pkcs1('PEM'))
    with open('KeysA/privateKeyA.pem', 'wb') as f:
        f.write(privateKey.save_pkcs1('PEM'))


# Load keys Tomka
"""""
def load_keys():
    with open('KeysA/publicKeyA.pem', 'rb') as f:
        publicKeyA = rsa.PublicKey.load_pkcs1(f.read())
    with open('KeysA/privateKeyA.pem', 'rb') as f:
        privateKey = rsa.PrivateKey.load_pkcs1(f.read())

    return publicKeyA, privateKey
"""""


def load_keys():
    with open('KeysA/publicKeyA.pem', 'rb') as f:
        publicKeyA = rsa.PublicKey.load_pkcs1(f.read())
    with open('KeysA/privateKeyA.pem', 'rb') as f:
        privateKeyA = rsa.PrivateKey.load_pkcs1(f.read())
    with open('KeysB/publicKeyB.pem', 'rb') as f:
        publicKeyB = rsa.PublicKey.load_pkcs1(f.read())
    with open('KeysB/privateKeyB.pem', 'rb') as f:
        privateKeyB = rsa.PrivateKey.load_pkcs1(f.read())

    return publicKeyA, privateKeyA, publicKeyB, privateKeyB


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False


def sign_sha1(message, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-1')


def verify_sha1(message, signature, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False


# Funkcje i 1 klasa Tomka do Local Key
# Funkcja bierze stringa od usera, tworzy ze stringa hash/klucz lokalny i tworzy pliki z zaszyfrowanymi kluczami RSA

def load_ecnrypted_keys():
    with open('KeysA/encryptedPublicKeyA.txt', 'r') as f:
        cipherPublicA = f.read()
    with open('KeysA/encryptedPrivateKeyA.txt', 'r') as f:
        cipherPrivateA = f.read()
    with open('KeysB/encryptedPublicKeyB.txt', 'r') as f:
        cipherPublicB = f.read()
    with open('KeysB/encryptedPrivateKeyB.txt', 'r') as f:
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

    with open('KeysA/encryptedPublicKeyA.txt', 'w') as f:
        f.write(cipherPublicA)
    with open('KeysA/encryptedPrivateKeyA.txt', 'w') as f:
        f.write(cipherPrivateA)
    with open('KeysB/encryptedPublicKeyB.txt', 'w') as f:
        f.write(cipherPublicB)
    with open('KeysB/encryptedPrivateKeyB.txt', 'w') as f:
        f.write(cipherPrivateB)


def decryptRSAKeysAndReturn():
    cipherPublicA, cipherPrivateA, cipherPublicB, cipherPrivateB = load_ecnrypted_keys()

    cbc = AESCipher()

    publicA = cbc.decrypt(str(cipherPublicA)).decode('utf-8')
    privateA = cbc.decrypt(cipherPrivateA).decode('utf-8')
    publicB = cbc.decrypt(cipherPublicB).decode('utf-8')
    privateB = cbc.decrypt(cipherPrivateB).decode('utf-8')

    return publicA, privateA, publicB, privateB


#  Keys
generate_keys()
# encryptRSAKeysAndSave()  # Zmiana Tomka
publicKeyA, privateKeyA, publicKeyB, privateKeyB = load_keys()
# decryptRSAKeysAndReturn()
print("Keys Generated")


#  Sockets
HOST = '192.168.1.12'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
PORT = 8888
BUFFER = 1024


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6
#server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))
server.listen(2)  # liczba miejsc w kolejce

print("Server A ONLINE")


#while True:
client, address = server.accept()
print(f"Uzyskano polaczenie od {address} | lub {address[0]}:{address[1]}")

#  RECEIVE NAME FROM CLIENT
name = client.recv(BUFFER).decode("utf8")
print(f"[{address[0]}{address[1]}]: Nazwa użytkownika: {name}")

msg = f"Witaj na serwie, {name}!".encode("utf8")
client.send(msg)


#  MAIN LOOP
#  WITH GUI
while True:
    TEST = client.recv(BUFFER).decode("utf8")
    print(TEST)
    if TEST == "message":
        print("we received a message my lord")

        msg = client.recv(BUFFER).decode("utf8")
        print(msg)

    if TEST == "file":
        print("a file has been received my liege")

        SEPARATOR = "<SEPARATOR>"
        received = client.recv(BUFFER).decode()
        filePath, fileSize = received.split(SEPARATOR)

        fileName = os.path.basename(filePath)
        fileSize = int(fileSize)
        print(fileSize)

        #progress
        with open("./test2/" + fileName, "wb") as f:
            c = 0

            startTime = time.time()

            while c < int(fileSize):
                data = client.recv(BUFFER)
                if not data:
                    break  # jesli nic nie dostaje przerwij
                f.write(data)
                c += len(data)
                # progress.update(len(bytes_read))

            endTime = time.time()

        print("plik odebrany:", endTime - startTime)


