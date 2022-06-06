#!/usr/bin/python
import threading
import time

class SendThread(threading.Thread):
    def __init__(self, threadID, name, client, HOST, PORT, BUFFER, os):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.client = client
        self.HOST = HOST
        self.PORT = PORT
        self.BUFFER = BUFFER
        self.os = os

    def run(self):
        print("Starting " + self.name)
        while True:
            TEST = self.client.recv(self.BUFFER).decode("utf8")
            print(TEST)
            if TEST == "message":
                print("we received a message my lord")

                msg = self.client.recv(self.BUFFER).decode("utf8")
                print(msg)

            if TEST == "file":
                print("a file has been received my liege")

                SEPARATOR = "<SEPARATOR>"
                received = self.client.recv(self.BUFFER).decode()
                filePath, fileSize = received.split(SEPARATOR)

                fileName = self.os.path.basename(filePath)
                fileSize = int(fileSize)
                print(str(fileSize), ' B, ', str(fileSize / 1024), ' KB, ', str(fileSize / 1048576), ' MB')

                # progress
                with open("./acquiredFiles/" + fileName, "wb") as f:
                    receivedDataSize = 0

                    startTime = time.time()

                    while receivedDataSize < int(fileSize):
                        data = self.client.recv(self.BUFFER)
                        if not data:
                            break  # jesli nic nie dostaje przerwij
                        f.write(data)
                        receivedDataSize += len(data)

                    endTime = time.time()

                print("plik odebrany:", endTime - startTime, ' s')

        print("Exiting " + self.name)

