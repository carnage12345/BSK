#!/usr/bin/python
import threading
import time
import os

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
        #global globalReceiveA

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

        while True:
            TEST = client.recv(self.BUFFER).decode("utf8")
            # print(TEST)
            if TEST == "message":
                print("we received a message my lord")
                msg = client.recv(self.BUFFER).decode("utf8")
                print(msg)
                self.q.put('You received a message:\n' + msg)

            if TEST == "file":
                print("a file has been received my liege")

                SEPARATOR = "<SEPARATOR>"
                received = client.recv(self.BUFFER).decode()
                filePath, fileSize = received.split(SEPARATOR)

                fileName = os.path.basename(filePath)
                fileSize = int(fileSize)  # fileSize in megabytes

                # print(str(fileSize), ' B, ', str(fileSize / 1024), ' KB, ', str(fileSize / 1048576), ' MB')

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
                    print("plik odebrany:", endTime - startTime, ' s')
                    self.q.put("plik odebrany:", endTime - startTime, ' s')
