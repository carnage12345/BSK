from RSAKeysLibrary import *
import socket

from os.path import exists
from queue import Queue
from Threads.ReceiveThread import ReceiveThread
from Threads.GuiThread import GuiThread

if __name__ == "__main__":

    #  Keys
    if not exists('./PublicKeys/publicKeyA.pem') or not exists('./PrivateKeys/privateKeyA.pem'):
        generate_keys('A')  # Wygenerowanie kluczy RSA

    # encryptRSAKeysAndSave()  # Utworzenie klucza lokalnego, zaszyfrowanie kluczy RSA kluczem lokalnym i zapisanie na dysku
    publicKeyA, privateKeyA = load_keys('A')
    # decryptRSAKeysAndReturn() # Odszyfrowanie kluczy RSA z dysku i zwrocenie ich jako zmienne

    #  Socket Receive
    receiveHOST = '192.168.1.12'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    receivePORT = 8888
    receiveBUFFER = 4194304  # 2097152 # 1048576   # 1024

    socketReceiveA = socket.socket(socket.AF_INET,
                                   socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

    # Socket Send

    sendHOST = '127.0.0.1'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    sendPORT = 8888
    sendBUFFER = 4194304  # 2097152 # 1048576   # 1024

    socketSendA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

    q = Queue()

    # Create threads
    receivingThreadA = ReceiveThread(1, 'A', socketReceiveA, receiveHOST, receivePORT, receiveBUFFER, q)
    GUIThreadA = GuiThread(2, 'A', socketSendA, sendHOST, sendPORT, sendBUFFER, q)  # threadID, name, socket, HOST, PORT, BUFFER)

    # Start threads
    receivingThreadA.start()
    GUIThreadA.start()
