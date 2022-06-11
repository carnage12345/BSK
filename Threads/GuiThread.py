import threading
import tkinter as tk
from tkinter import ttk
from tkinter import OptionMenu
from tkinterLibrary import button_set_password
from RSAKeysLibrary import *
from tkinterLibrary import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

user_friendly_password = 0


class GuiThread(threading.Thread):
    def __init__(self, threadID, name, socket, HOST, PORT, BUFFER, queue):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.socket = socket
        self.HOST = HOST
        self.PORT = PORT
        self.BUFFER = BUFFER
        self.q = queue
        self.password = 0

    def run(self):
        print("Starting " + self.name + " GUI Thread")

        self.socket.connect((self.HOST, self.PORT))  # CONNECT TO SERVER

        #  SEND NAME TO SERVER
        self.socket.send((self.name + 'lek').encode('utf8'))
        print(self.socket.recv(self.BUFFER).decode("utf8"))

        #  RECEIVE PUBLIC KEY FROM SERVER
        publicKey, privateKey = load_keys(self.name)  # decryptRSAKeysAndReturn(self.name)

        clientPublicKey = rsa.key.PublicKey.load_pkcs1(self.socket.recv(self.BUFFER), format='PEM')  # DER
        print(clientPublicKey)

        #  SEND PUBLIC KEY TO SERVER
        print("wysyłam klucz do Serwera")
        print(publicKey)
        self.socket.send(publicKey.save_pkcs1(format='PEM'))
        print("klucz wysłany\n")

        print("CREATING SESSION KEY:")

        sessionKeyRandom = os.urandom(16)  # PODMIENIĆ NA TO!!!!

        # SEND SESSION KEY TO SERVER
        print("sending session KEY")
        print(sessionKeyRandom)
        ciphertext = encrypt_session_key_with_rsa(sessionKeyRandom, clientPublicKey)  # zamienic na sessionKey3Random
        # signature
        self.socket.send(ciphertext)
        print("sent session KEY\n")

        #  TKINTER
        window = tk.Tk()
        window.title('Client ' + self.name)
        # window.geometry('300x500')
        window.geometry('500x500')

        #  GLOBALS FOR tk #
        pathStringVar = tk.StringVar()
        pathStringVar.set("path to the file we are sending")

        #  tk MAIN PROGRAM
        tk.Label(window, text='BSK Project').pack()
        tk.Label(window, text='Message:').pack()
        entry = tk.Entry(window)
        entry.pack()
        sendButton = tk.Button(window, text='send message', command=lambda: button_send_message(entry, self.socket))
        sendButton.pack()
        tk.Label(window, textvariable=pathStringVar).pack()

        tk.Label(window, text='Enter your user-friendly password:').pack()
        password_entry = tk.Entry(window)
        password_entry.pack()

        def get_password():
            global user_friendly_password
            user_friendly_password = password_entry.get()

        def printing():
            print(user_friendly_password)

        tk.Button(window, text="Set password",
                                           command=lambda: get_password()).pack()
        tk.Button(window, text="Print variable",
                  command=lambda: printing()).pack()


        # pb = Progress Bar
        tk.Label(window, text='Progress Bar:').pack()
        pb = ttk.Progressbar(window, orient='horizontal', mode='determinate', length=280)
        pb.pack()

        pbDescription = ttk.Label(window, text="Current Progress: 0%")
        pbDescription.pack()

        fileOpenButton = tk.Button(window, text='file dialog', command=lambda: button_open_file_function(pathStringVar))
        fileOpenButton.pack()

        tk.Label(window, text='Choose ciphering mode:').pack()

        clicked = tk.StringVar()
        clicked.set("ECB")  # default value
        options = [
            'ECB',
            'CBC'
        ]

        OptionMenu(window, clicked, *options).pack()

        cipheringMode = clicked.get()
        print(cipheringMode)

        entry_encoded = tk.Entry(window)
        entry_encoded.pack()

        sendButtonEncoded = tk.Button(window, text='send message Encoded RSA',
                                      command=lambda: send_message_encoded_rsa(entry_encoded, self.socket, publicKey,
                                                                               privateKey))
        sendButtonEncoded.pack()

        #  message encoded with CBC
        entry_CBC = tk.Entry(window)
        entry_CBC.pack()

        tk_sendButtonCBC = tk.Button(window, text='send message Encoded CBC',
                                     command=lambda: send_message_encoded_cbc(entry_CBC, 'Nicosc', pad, self.socket))
        tk_sendButtonCBC.pack()

        fileSendButton = tk.Button(window, text='send file',
                                   command=lambda: button_send_file_function(self.socket, self.BUFFER,
                                                                             pathStringVar.get(), pb, pbDescription,
                                                                             window))
        fileSendButton.pack()

        tk.Label(window, text='Received section:').pack()

        receivedContent = tk.StringVar()
        receivedContent.set('nothing')

        tk.Button(window, text='check', command=lambda: check_queue(self.q, receivedContent)).pack()
        ttk.Label(window, textvariable=receivedContent).pack()

        window.mainloop()
