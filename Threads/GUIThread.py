import threading
import tkinter as tk
from tkinter import ttk
from tkinterLibrary import *


class GUIThread(threading.Thread):
    def __init__(self, threadID, name, socket, HOST, PORT, BUFFER):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.socket = socket
        self.HOST = HOST
        self.PORT = PORT
        self.BUFFER = BUFFER

    def run(self):
        print("Starting " + self.name + " GUI Thread")

        self.socket.connect((self.HOST, self.PORT))  # CONNECT TO SERVER

        #  SEND NAME TO SERVER
        self.socket.send((self.name + 'lek').encode('utf8'))
        print(self.socket.recv(self.BUFFER).decode("utf8"))


        #  tk
        window = tk.Tk()
        window.title('Client ' + self.name)
        window.geometry('300x500')

        #  GLOBALS FOR tk #
        path_string_var = tk.StringVar()
        path_string_var.set("path to the file we are sending")

        #  tk MAIN PROGRAM
        title = tk.Label(window, text='BSK Project')
        title.pack()

        message = tk.Label(window, text='Message:')
        message.pack()

        entry = tk.Entry(window)
        entry.pack()

        sendButton = tk.Button(window, text='send message', command=lambda: button_send_message(entry, self.socket))
        sendButton.pack()

        path_label = tk.Label(window, textvariable=path_string_var)
        path_label.pack()

        # pb = Progress Bar
        pb_label = tk.Label(window, text='Progress Bar:')  # .grid(column=0, row=3, padx=10, pady=10, sticky=tk.E)
        pb_label.pack()

        pb = ttk.Progressbar(window, orient='horizontal', mode='determinate', length=280)  # .grid(column=0, row=4, padx=10, pady=10, sticky=tk.E)
        pb.pack()

        pb_value = ttk.Label(window,text="Current Progress: 0%")  # .grid(column=0, row=5, padx=10, pady=10, sticky=tk.E)
        pb_value.pack()

        fileOpenButton = tk.Button(window, text='file dialog',command=lambda: button_open_file_function(path_string_var))
        fileOpenButton.pack()

        fileSendButton = tk.Button(window, text='send file', command=lambda: button_send_file_function(self.socket, self.BUFFER, path_string_var.get(), pb, pb_value))
        fileSendButton.pack()

        window.mainloop()

        print("Exiting " + self.name)
