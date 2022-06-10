import threading
import tkinter as tk
from tkinter import ttk
from tkinter import OptionMenu

from tkinterLibrary import *


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

    def run(self):
        print("Starting " + self.name + " GUI Thread")

        self.socket.connect((self.HOST, self.PORT))  # CONNECT TO SERVER

        #  SEND NAME TO SERVER
        self.socket.send((self.name + 'lek').encode('utf8'))
        print(self.socket.recv(self.BUFFER).decode("utf8"))

        #  tk
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

        fileSendButton = tk.Button(window, text='send file',
                                   command=lambda: button_send_file_function(self.socket, self.BUFFER,
                                                                             pathStringVar.get(), pb, pbDescription,
                                                                             window))
        fileSendButton.pack()

        tk.Label(window, text='Received section:').pack()

        receivedContent = tk.StringVar()
        receivedContent.set('nothing')

        # def check_queue():
        #     if self.q.empty():
        #         print('queue is empty')
        #         receivedContent.set('nothing')
        #     else:
        #         print('queue is not empty')
        #         receivedContent.set(self.q.get())
        #
        # tk.Button(window, text='check', command=check_queue).pack()

        tk.Button(window, text='check', command=lambda: check_queue(self.q, receivedContent)).pack()
        ttk.Label(window, textvariable=receivedContent).pack()

        window.mainloop()
