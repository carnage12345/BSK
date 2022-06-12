import rsa
import hashlib

from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

#  RSA key functions
# Jaworski
def generate_keys(letter):
    # (publicKey, privateKey) = rsa.newkeys(1024)  # 1024 - 128 byte key
    # with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'wb') as f:
    #     f.write(publicKey.save_pkcs1('PEM'))
    # with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'wb') as f:
    #     f.write(privateKey.save_pkcs1('PEM'))
    # print("Keys Generated")

    key = RSA.generate(1024)
    publicKey = key.publickey().exportKey('PEM')
    privateKey = key.exportKey()
    #print(publicKey)
    with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'wb') as f:
        f.write(publicKey)
    with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'wb') as f:
        f.write(privateKey)
    print("Keys Generated")


def load_keys(letter):
    # with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'rb') as f:
    #     publicKey = rsa.PublicKey.load_pkcs1(f.read())
    # with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'rb') as f:
    #     privateKey = rsa.PrivateKey.load_pkcs1(f.read())
    #
    # return publicKey, privateKey

    # with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'rb') as f:
    #     publicKey = RSA.import_key(f.read())
    # with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'rb') as f:
    #     privateKey = RSA.import_key(f.read())
    #
    # return publicKey, privateKey


    with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'rb') as f:
        publicKey = f.read()
    with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'rb') as f:
        privateKey = f.read()

    return publicKey, privateKey

# with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'rb') as f:
#     publicKey = serialization.load_pem_public_key(f.read(), backend=default_backend())
# with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'rb') as f:
#     privateKey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
#
# return publicKey, privateKey


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


def encrypt_session_key_with_rsa(session_key, rsa_key):
    return rsa.encrypt(session_key, rsa_key)


def decrypt_session_key_with_rsa(session_key_encoded, rsa_kye):
    try:
        return rsa.decrypt(session_key_encoded, rsa_kye)
    except:
        return False


# Żebrowski

class AESCipher:
    def __init__(self, user_friendly_password):
        password = user_friendly_password
        self.local_key = hashlib.md5(password.encode('utf8')).digest()
        self.cipher = 'nothing'

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.local_key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), AES.block_size)))
        # return b64encode(iv + self.cipher.encrypt(pad(data, AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.local_key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


def load_encrypted_keys(letter):
    #with open('./Keys' + letter + '/PublicKeys/encryptedPublicKey' + letter + '.txt', 'r') as f:
    with open('./Keys' + letter + '/PublicKeys/encryptedPublicKey' + letter + '.pem', 'r') as f:
        cipheredPublicKey = f.read()
    #with open('./Keys' + letter + '/PrivateKeys/encryptedPrivateKey' + letter + '.txt', 'r') as f:
    with open('./Keys' + letter + '/PrivateKeys/encryptedPrivateKey' + letter + '.pem', 'r') as f:
        cipheredPrivateKey = f.read()

    return cipheredPublicKey, cipheredPrivateKey


def encrypt_RSA_keys_and_save(letter, user_friendly_password):
    cbc = AESCipher(user_friendly_password)
    publicKey, privateKey = load_keys(letter)

    # print('szyfrowanie: ')
    # print(publicKey)
    #publicKeyAsString = str(publicKey)
    # print(publicKeyAsString)


    publicKey = serialization.load_pem_public_key(publicKey, backend=default_backend())
    privateKey = serialization.load_pem_private_key(privateKey, password=None, backend=default_backend())

    print(publicKey)

    # DZIALA SERIALIZACJA
    public_pem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print('public-pem: ')
    zmienna = str(public_pem)
    print(zmienna)


    # public_key2 = serialization.load_pem_public_key(publicKey, default_backend())
    # print(public_key2)

    # print('PEM publiczny' + publicKey)
    # print('PEM prywatny' + privateKey)

    # cert = x509.load_pem_x509_certificate(publicKey, default_backend())
    # cert.serial_number
    # print('PEM publiczny' + cert.serial_number)
    # print('PEM prywatny' + cert.serial_number)
    #
    # print('SKonwertonway na string publiczny: ' + str(publicKey))
    # print('SKonwertonway na string prywatny: ' + str(privateKey))

    # substrate = pem.readPemFromFile(open('cert.pem'))
    # cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
    # print(cert.prettyPrint())

    # cipheredPublicKey = cbc.encrypt(str(publicKey)).decode('utf-8')
    # cipheredPrivateKey = cbc.encrypt(str(privateKey)).decode('utf-8')

    cipheredPublicKey = cbc.encrypt(str(publicKey)).decode('utf-8')
    cipheredPrivateKey = cbc.encrypt(str(privateKey)).decode('utf-8')
    # f.write(publicKey.save_pkcs1('PEM'))
    with open('./Keys' + letter + '/PublicKeys/encryptedPublicKey' + letter + '.pem', 'w') as f:
        f.write(cipheredPublicKey)
        # f.write(cipheredPublicKey.save_pkcs1('PEM'))
    with open('./Keys' + letter + '/PrivateKeys/encryptedPrivateKey' + letter + '.pem', 'w') as f:
        f.write(cipheredPrivateKey)
        # f.write(cipheredPrivateKey.save_pkcs1('PEM'))


def decrypt_RSA_keys_and_return(letter, user_friendly_password):
    cbc = AESCipher(user_friendly_password)
    cipheredPublicKey, cipheredPrivateKey = load_encrypted_keys(letter)

    publicKey = cbc.decrypt(cipheredPublicKey).decode('utf-8')
    privateKey = cbc.decrypt(cipheredPrivateKey).decode('utf-8')
    print(publicKey)
    print(privateKey)
#    publicKey = RSA.import_key(publicKey)
#    privateKey = RSA.import_key(privateKey)

    # print('publiczny_pem: ')
    # print(publicKey)
    # print('prywatny_pem: ')
    # print(privateKey)

    return publicKey, privateKey
