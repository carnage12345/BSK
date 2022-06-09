import threading
import tkinter as tk
from tkinter import ttk
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
        title = tk.Label(window, text='BSK Project')
        title.pack()

        message = tk.Label(window, text='Message:')
        message.pack()

        entry = tk.Entry(window)
        entry.pack()

        sendButton = tk.Button(window, text='send message', command=lambda: button_send_message(entry, self.socket))
        sendButton.pack()

        pathLabel = tk.Label(window, textvariable=pathStringVar)
        pathLabel.pack()

        # pb = Progress Bar
        pbLabel = tk.Label(window, text='Progress Bar:')  # .grid(column=0, row=3, padx=10, pady=10, sticky=tk.E)
        pbLabel.pack()

        pb = ttk.Progressbar(window, orient='horizontal', mode='determinate',
                             length=280)  # .grid(column=0, row=4, padx=10, pady=10, sticky=tk.E)
        pb.pack()

        pbDescription = ttk.Label(window,
                                  text="Current Progress: 0%")  # .grid(column=0, row=5, padx=10, pady=10, sticky=tk.E)
        pbDescription.pack()

        fileOpenButton = tk.Button(window, text='file dialog',
                                   command=lambda: button_open_file_function(pathStringVar))
        fileOpenButton.pack()

        fileSendButton = tk.Button(window, text='send file',
                                   command=lambda: button_send_file_function(self.socket, self.BUFFER,
                                                                             pathStringVar.get(), pb, pbDescription, window))
        fileSendButton.pack()

        receivedLabel = tk.Label(window, text='Received section:')
        receivedLabel.pack()

        receivedContent = tk.StringVar()
        receivedContent.set('nothing')


        def check_queue():
            if (self.q.empty()):
                print('queue is empty')
                receivedContent.set('nothing')
            else:
                print('queue is not empty')
                receivedContent.set(self.q.get())

        checkReceiveButton = tk.Button(window, text='check', command=check_queue)
        checkReceiveButton.pack()

        receivedValue = ttk.Label(window, textvariable=receivedContent)
        receivedValue.pack()

        window.mainloop()
