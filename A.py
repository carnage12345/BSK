import socket
from os.path import exists
from queue import Queue
from RSAKeysLibrary import *
from Threads.ReceiveThread import ReceiveThread
from Threads.GuiThread import GuiThread
from Threads.GuiThread import get_password

# Create RSA Keys
#if not exists('./KeysA/PublicKeys/publicKeyA.pem') or not exists('./KeysA/PrivateKeys/privateKeyA.pem'):
#    generate_keys('A')

generate_keys('A')

encrypt_RSA_keys_and_save('A', get_password())
publicKey, privateKey = decrypt_RSA_keys_and_return('A', get_password())

# print('Odszyfrowany Publiczny A: ' + publicKey)
# print('Odszyfrowany Prywatny A: ' + privateKey)
#
# # Create Sockets
# # Socket for receiving data
# receiveHOST = '192.168.1.12'  # tomek - 192.168.1.12 ,jakub - 192.168.0.193, dla wszystkich 127.0.0.1
# receivePORT = 8888
# receiveBUFFER = 4194304
# socketReceiveA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
# # Socket for sending data
# sendHOST = '127.0.0.1'  # tomek - 192.168.1.12 ,jakub - 192.168.0.193, dla wszystkich 127.0.0.1
# sendPORT = 8888
# sendBUFFER = 4194304  # 2097152 # 1048576   # 1024
# socketSendA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6
#
# # Create Queue
# queue = Queue()
#
# # Create threads
# receivingThreadA = ReceiveThread(1, 'A', socketReceiveA, receiveHOST, receivePORT, receiveBUFFER, queue)
# GUIThreadA = GuiThread(2, 'A', socketSendA, sendHOST, sendPORT, sendBUFFER, queue)
#
# # Start threads
# receivingThreadA.start()
# GUIThreadA.start()
