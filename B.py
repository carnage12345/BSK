import socket
from RSAKeysLibrary import *
from os.path import exists
from queue import Queue
from Threads.ReceiveThread import ReceiveThread
from Threads.GuiThread import GuiThread


# Create RSA Keys
if not exists('./KeysB/PublicKeys/publicKeyB.pem') or not exists('./KeysB/PrivateKeys/privateKeyB.pem'):
    generate_keys('B')  # Wygenerowanie kluczy RSA

# Create Sockets
# Socket for receiving data
receiveHOST = '127.0.0.1'   # tomek - 192.168.1.12 ,jakub - 192.168.0.193, dla wszystkich 127.0.0.1
receivePORT = 8888
receiveBUFFER = 4194304
socketReceiveB = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# Socket for sending data
sendHOST = '192.168.1.12'  # tomek - 192.168.1.12 ,jakub - 192.168.0.193, dla wszystkich 127.0.0.1
sendPORT = 8888
sendBUFFER = 4194304
socketSendB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create Queue
q = Queue()

# Create threads
receivingThreadB = ReceiveThread(1, 'B', socketReceiveB, receiveHOST, receivePORT, receiveBUFFER, q)
GUIThreadB = GuiThread(2, 'B', socketSendB, sendHOST, sendPORT, sendBUFFER, q)

# Start threads
receivingThreadB.start()
GUIThreadB.start()
