import socket
from tkinterLibrary import *
from RSAKeysLibrary import generate_keys, load_keys
from os.path import exists
from Threads.ReceiveThread import ReceiveThread
from Threads.GUIThread import GUIThread


if __name__ == "__main__":
    # Keys
    if not exists('./PublicKeys/publicKeyB.pem') or not exists('./PrivateKeys/privateKeyB.pem'):
        generate_keys('B')  # Wygenerowanie kluczy RSA

    # encryptRSAKeysAndSave()  # Utworzenie klucza lokalnego, zaszyfrowanie kluczy RSA kluczem lokalnym i zapisanie na dysku
    publicKeyB, privateKeyB = load_keys('B')
    # decryptRSAKeysAndReturn() # Odszyfrowanie kluczy RSA z dysku i zwrocenie ich jako zmienne

    # Keys test
    # encrypt_decrypt_message(publicKeyB, privateKeyB)

    #  Sockets
    receiveHOST = '127.0.0.1'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    receivePORT = 8888
    receiveBUFFER = 4194304  # 2097152 # 1048576   # 1024

    socketReceiveB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

    sendHOST = '192.168.1.12'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    sendPORT = 8888
    sendBUFFER = 4194304  # 2097152 # 1048576   # 1024

    socketSendB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

    # Create threads
    receivingThreadB = ReceiveThread(1, 'B', socketReceiveB, receiveHOST, receivePORT, receiveBUFFER)
    GUIThreadB = GUIThread(2, 'B', socketSendB, sendHOST, sendPORT, sendBUFFER)

    # Start threads
    receivingThreadB.start()
    GUIThreadB.start()