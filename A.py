from RSAKeysLibrary import *
import socket  # https://www.geeksforgeeks.org/socket-programming-python/

from os.path import exists
from Threads.ReceiveThread import ReceiveThread
from Threads.GUIThread import GUIThread

if __name__ == "__main__":

    #  Keys
    if not exists('./PublicKeys/publicKeyA.pem') or not exists('./PrivateKeys/privateKeyA.pem'):
        generate_keys('A')  # Wygenerowanie kluczy RSA

    # encryptRSAKeysAndSave()  # Utworzenie klucza lokalnego, zaszyfrowanie kluczy RSA kluczem lokalnym i zapisanie na dysku
    publicKeyA, privateKeyA = load_keys('A')
    # decryptRSAKeysAndReturn() # Odszyfrowanie kluczy RSA z dysku i zwrocenie ich jako zmienne


    #  Sockets
    receiveHOST = '192.168.1.12'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    receivePORT = 8888
    receiveBUFFER = 4194304  # 2097152 # 1048576   # 1024

    socketReceiveA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

    sendHOST = '127.0.0.1'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    sendPORT = 8888
    sendBUFFER = 4194304  # 2097152 # 1048576   # 1024

    socketSendA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

    # Create threads
    receivingThreadA = ReceiveThread(1, "A", socketReceiveA, receiveHOST, receivePORT, receiveBUFFER)
    GUIThreadA = GUIThread(2, "A", socketSendA, sendHOST, sendPORT, sendBUFFER) #  threadID, name, socket, HOST, PORT, BUFFER)

    # Start threads
    receivingThreadA.start()
    GUIThreadA.start()


