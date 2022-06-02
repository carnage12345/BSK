from RSAKeysLibrary import *
import socket  # https://www.geeksforgeeks.org/socket-programming-python/
import time
import os

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
    BUFFER = 4194304 # 2097152 # 1048576   # 1024


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
            # print(fileSize)
            print(str(fileSize), ' B, ', str(fileSize / 1024), ' KB, ', str(fileSize / 1048576), ' MB')

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

            print("plik odebrany:", endTime - startTime, ' s')


