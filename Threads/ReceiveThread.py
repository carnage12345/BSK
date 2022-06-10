#!/usr/bin/python
import threading
import time
import os
from RSAKeysLibrary import *

class ReceiveThread(threading.Thread):
    def __init__(self, threadID, name, socket, HOST, PORT, BUFFER, queue):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.socket = socket
        self.HOST = HOST
        self.PORT = PORT
        self.BUFFER = BUFFER
        self.q = queue

    def run(self):
        # global globalReceiveA

        print("Starting " + self.name + " receive thread")

        self.socket.bind((self.HOST, self.PORT))
        self.socket.listen(2)  # liczba miejsc w kolejce
        print(self.BUFFER)
        print("Server " + self.name + " ONLINE")

        client, address = self.socket.accept()
        print(f"Uzyskano polaczenie od {address} | lub {address[0]}:{address[1]}")

        #  RECEIVE NAME FROM CLIENT
        nick = client.recv(self.BUFFER).decode("utf8")
        print(f"[{address[0]}{address[1]}]: Nazwa użytkownika: {nick}")

        msg = f"Witaj na serwerze , {nick}!".encode("utf8")
        client.send(msg)

        # JAWORSKI ZMIANA 1

        publicKey, privateKey = load_keys(self.name)

        #  SEND PUBLIC KEY TO CLIENT (also receive key from client)
        print("wysyłam klucz publiczny (A)")
        print(publicKey)
        client.send(publicKey.save_pkcs1(format='PEM'))
        print("klucz wysłany\n")

        # RECEIVE PUBLIC KEY FROM CLIENT
        print("odbieram public key (B)\n")
        clientPublicKey = rsa.key.PublicKey.load_pkcs1(client.recv(self.BUFFER), format='PEM')  # DER
        print("publicKeyB: " + str(clientPublicKey))

        # RECEIVE SESSION KEY FROM CLIENT
        print("odbieram session key\n")
        sessionKey = decrypt_session_key_with_rsa(client.recv(self.BUFFER), privateKey)
        print("sessionKey: " + str(sessionKey))

        while True:
            TEST = client.recv(self.BUFFER).decode("utf8")

            if TEST == "message":
                msg = client.recv(self.BUFFER).decode("utf8")
                self.q.put('You received a message:\n' + msg)

            if TEST == "file":

                SEPARATOR = "<SEPARATOR>"
                received = client.recv(self.BUFFER).decode()
                filePath, fileSize = received.split(SEPARATOR)

                fileName = os.path.basename(filePath)
                fileSize = int(fileSize)  # fileSize in bytes

                # progress
                with open("./acquiredFiles/" + fileName, "wb") as f:
                    receivedDataSize = 0

                    startTime = time.time()

                    while receivedDataSize < int(fileSize):
                        data = client.recv(self.BUFFER)
                        if not data:
                            break  # no data means that full file has been received
                        f.write(data)
                        receivedDataSize += len(data)

                    endTime = time.time()
                    # print("plik odebrany:", endTime - startTime, ' s')
                    self.q.put('You received a file:\nName: ' + fileName + '\nPath: ' + str(os.getcwd()) +
                               '\\acquiredFiles\\' + fileName + '\nSize: ' + str(fileSize / 1048576) +
                               ' MB\nTransfer time: ' + str(endTime - startTime) + ' s')

            if TEST == "message_encoded":
                print("we received a secret message from our spies my lord...")
                msg = client.recv(self.BUFFER)
                print("message encrypted:")
                print(msg)
                print("message decrypted:")
                print(decrypt(msg, privateKey))

            if TEST == "message_encoded_cbc":
                print("CBC message has entered the castle")
                iVectorCBC = client.recv(self.BUFFER)
                ciphertext = client.recv(self.BUFFER)
                print("message encrypted:")
                print(ciphertext)
                print("message decrypted:")
                cipher = AES.new(sessionKey, AES.MODE_CBC, iVectorCBC)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                print(plaintext)
