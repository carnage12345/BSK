from RSAKeysLibrary import *
import socket  # https://www.geeksforgeeks.org/socket-programming-python/
import os

from ReceiveThread import ReceiveThread

if __name__ == "__main__":
    #  Keys
    generate_keys('A')  # Wygenerowanie kluczy RSA
    # encryptRSAKeysAndSave()  # Utworzenie klucza lokalnego, zaszyfrowanie kluczy RSA kluczem lokalnym i zapisanie na dysku
    publicKeyA, privateKeyA = load_keys('A')
    # decryptRSAKeysAndReturn() # Odszyfrowanie kluczy RSA z dysku i zwrocenie ich jako zmienne
    print("Keys Generated")

    #  Sockets
    HOST = '192.168.1.12'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    PORT = 8888
    BUFFER = 4194304  # 2097152 # 1048576   # 1024

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6
    server.bind((HOST, PORT))
    server.listen(2)  # liczba miejsc w kolejce

    print("Server A ONLINE")

    client, address = server.accept()
    print(f"Uzyskano polaczenie od {address} | lub {address[0]}:{address[1]}")

    #  RECEIVE NAME FROM CLIENT
    name = client.recv(BUFFER).decode("utf8")
    print(f"[{address[0]}{address[1]}]: Nazwa użytkownika: {name}")

    msg = f"Witaj na serwie, {name}!".encode("utf8")
    client.send(msg)


   #  def __init__(self, threadID, name, client, HOST, PORT, BUFFER, os):
    A_receiving_thread = ReceiveThread(1, "A - Watek wysylajacy", client, HOST, PORT, BUFFER, os)

    # Start new Threads
    A_receiving_thread.start()

    print("Exiting Main Thread")

    #  MAIN LOOP
    #  WITH GUI
    """"
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
            print(str(fileSize), ' B, ', str(fileSize / 1024), ' KB, ', str(fileSize / 1048576), ' MB')

            #progress
            with open("./acquiredFiles/" + fileName, "wb") as f:
                receivedDataSize = 0

                startTime = time.time()

                while receivedDataSize < int(fileSize):
                    data = client.recv(BUFFER)
                    if not data:
                        break  # jesli nic nie dostaje przerwij
                    f.write(data)
                    receivedDataSize += len(data)

                endTime = time.time()

            print("plik odebrany:", endTime - startTime, ' s')
"""



