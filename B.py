import socket
import tkinter as tk
from tkinter.messagebox import showinfo
from tkinter import ttk
from tkinterLibrary import *
from RSAKeysLibrary import generate_keys, load_keys

if __name__ == "__main__":

    # Keys
    generate_keys('B')
    publicKeyB, privateKeyB = load_keys('B')
    print("Keys Generated")

    # Keys test
    encrypt_decrypt_message(publicKeyB, privateKeyB)

    #  Sockets
    HOST = '192.168.1.12'  # 127.0.0.1 /// 0.0.0.0 /// 89.64.149.219 # IP = socket.gethostbyname(socket.gethostname())
    PORT = 8888
    BUFFER = 1024

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # creating socket
    client.connect((HOST, PORT))  # CONNECT TO SERVER

    #  SEND NAME TO SERVER
    name = "bolek".encode("utf8")  # input('Twoje imie: ').encode("utf8")
    client.send(name)
    print(client.recv(BUFFER).decode("utf8"))

    #  tk
    window = tk.Tk()
    window.geometry('300x500')

    #  GLOBALS FOR tk #
    file_path_test = "path to the file we are sending"  # ZMIENIC NAZWE TEJ ZMIENNEJ NA COS LEPSZEGO
    text_variable_label2 = tk.StringVar()
    text_variable_label2.set(file_path_test)


    #  tk MAIN PROGRAM
    title = tk.Label(window, text='BSK Project').pack()
    message = tk.Label(window, text='Message:').pack()
    entry = tk.Entry(window).pack()
    sendButton = tk.Button(window, text='send message', command=lambda: button_send_message(entry, client)).pack()
    tk_label2 = tk.Label(window, textvariable=text_variable_label2).pack()
    fileOpenButton = tk.Button(window, text='file dialog', command=button_open_file_function).pack()
    fileSendButton = tk.Button(window, text='send file', command=button_send_file_function).pack()

    # TOMEK Progress Bar
    bar_label = tk.Label(window, text='Progress Bar:').pack()
    pb = ttk.Progressbar(window, orient='horizontal', mode='determinate', length=280).pack()
    progress_bar_value = ttk.Label(window, text=progress).pack()
    value_label = ttk.Label(window, text=update_progress_label).pack()

    window.mainloop()
