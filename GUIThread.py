import threading
import tkinter as tk
from tkinter import ttk
from tkinterLibrary import *


class GUIThread(threading.Thread):
    def __init__(self, threadID, name, client, BUFFER):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.client = client
        self.BUFFER = BUFFER

    def run(self):
        print("Starting " + self.name)

        #  tk
        window = tk.Tk()
        window.title('Client B')
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

        sendButton = tk.Button(window, text='send message', command=lambda: button_send_message(entry, self.client))
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

        fileSendButton = tk.Button(window, text='send file',command=lambda: button_send_file_function(self.client, self.BUFFER, path_string_var.get(), pb, pb_value))
        fileSendButton.pack()

        window.mainloop()

        print("Exiting " + self.name)
