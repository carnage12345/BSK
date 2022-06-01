import socket
import tkinter
from tkinter import filedialog
import rsa
from tkinter import ttk
import tkinter as tk
from tkinter.messagebox import showinfo
import tqdm
import time

import os  # co to jest???


#  RSA key functions
def generate_keys():
    (publicKey, privateKey) = rsa.newkeys(1024)  # 1024 - 128 bitowy klucz
    with open('KeysB/publicKeyB.pem', 'wb') as f:
        f.write(publicKey.save_pkcs1('PEM'))
    with open('KeysB/privateKeyB.pem', 'wb') as f:
        f.write(privateKey.save_pkcs1('PEM'))


def load_keys():
    with open('KeysB/publicKeyB.pem', 'rb') as f:
        publicKey = rsa.PublicKey.load_pkcs1(f.read())
    with open('KeysB/privateKeyB.pem', 'rb') as f:
        privateKey = rsa.PrivateKey.load_pkcs1(f.read())
    return publicKey, privateKey


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False


def sign_sha1(message, key):  # sign and verify with key
    return rsa.sign(message.encode('ascii'), key, 'SHA-1')


def verify_sha1(message, signature, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False


#  -----------------
#  tkinter functions
#  -----------------
def tk_button_send_message_function():
    message = tk_entry.get()
    print(message)
    client.send("message".encode("utf8"))
    client.send(message.encode("utf8"))


def tk_button_send_message_function_encoded():
    message = tk_entry.get()
    print(message)

    ciphertext = encrypt(message, publicKey)
    signature = sign_sha1(message, privateKey)

    client.send("message_encoded".encode("utf8"))
    client.send(message.encode("utf8"))


def encrypt_decrypt_message():
    message = "here i come"
    print(message)
    ciphertext = encrypt(message, publicKey)
    signature = sign_sha1(message, privateKey)
    plaintext = decrypt(ciphertext, privateKey)

    print(f"CipherText:{ciphertext}")
    print(f"Signature:{signature}")

    if plaintext:
        print(f"PlainText: {plaintext}")
    else:
        print("encryption-decryption failed")

    if verify_sha1(plaintext, signature, publicKey):
        print("signature verified")
    else:
        print("Could not verift the message signature")


def tk_button_open_file_function():
    file_path = filedialog.askopenfilename(title="BSK - which file to open?",
                                           filetypes=(("txt files", "*.txt"),
                                                      ("all files", "*.*"),
                                                      ("png files", "*.png"),
                                                      ("pdf files", "*.pdf"),
                                                      ("avi files", "*.avi"),
                                                      ("jpg files", "*.jpg")))
    print(file_path)
    # file = open(file_path, 'r')
    # print(file.read())
    # file.close()
    global file_path_test
    file_path_test = file_path
    text_variable_label2.set(file_path_test)


def tk_button_send_file_function():
    client.send("file".encode("utf8"))

    SEPARATOR = "<SEPARATOR>"
    filePath = file_path_test
    fileSize = os.path.getsize(filePath)

    client.send(f"{filePath}{SEPARATOR}{fileSize}".encode())

    print(filePath)

    print(fileSize)
    with open(filePath, "rb") as f:
        c = 0
        startTime = time.time()
        while c < fileSize:
            data = f.read(BUFFER)
            if not data:
                break
            client.sendall(data)
            c += len(data)
            # progress.update(len(bytes_read))
            progress(c, fileSize)
        endTime = time.time()

    print("File transfer complete:", endTime - startTime, " s")


#  Keys
generate_keys()
publicKey, privateKey = load_keys()
print("Keys Generated")

# test kluczy
encrypt_decrypt_message()

#  Sockets
HOST = '192.168.1.12'  # 127.0.0.1 /// 0.0.0.0 /// 89.64.149.219 # IP = socket.gethostbyname(socket.gethostname())
PORT = 8888
BUFFER = 1024

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # creating socket
# client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.connect((HOST, PORT))  # CONNECT TO SERVER

#  SEND NAME TO SERVER
name = "bolek".encode("utf8")

# input('Twoje imie: ').encode("utf8")
client.send(name)
print(client.recv(BUFFER).decode("utf8"))

#  -------
#  TKINTER
#  -------
tk_window = tkinter.Tk()
tk_window.geometry('300x500')

#  -------------------
#  GLOBALS FOR TKINTER #
#  zmienne globalne do tkintera
#  (aby użyć zmiennej w argumencie ->lambda, zwrot niemożliwy w łatwy sposób dlatego lepiej globalne)
#  -------------------
file_path_test = "path to the file we are sending"  # ZMIENIC NAZWE TEJ ZMIENNEJ NA COS LEPSZEGO
text_variable_label2 = tkinter.StringVar()
text_variable_label2.set(file_path_test)

#  -------
#  TKINTER MAIN PROGRAM
#  -------
tk_titleLabel = tkinter.Label(tk_window, text='BSK Project')
tk_titleLabel.pack()

tk_label1 = tkinter.Label(tk_window, text='Message:')
tk_label1.pack()

tk_entry = tkinter.Entry(tk_window)
tk_entry.pack()

tk_sendButton = tkinter.Button(tk_window, text='send message', command=tk_button_send_message_function)
tk_sendButton.pack()  # side=tkinter.TOP #  x = 0, y = 0

tk_label2 = tkinter.Label(tk_window, textvariable=text_variable_label2)
tk_label2.pack()

# tk_fileButton = tkinter.Button(tk_root, text='file dialog',
# command=lambda: tk_button_open_file_function(file_path_test))
# lambda pozwala przekazać do tkintera funckje z argumentem
tk_fileOpenButton = tkinter.Button(tk_window, text='file dialog', command=tk_button_open_file_function)
tk_fileOpenButton.pack()

tk_fileSendButton = tkinter.Button(tk_window, text='send file', command=tk_button_send_file_function)
tk_fileSendButton.pack()


# TOMEK zmiany

def update_progress_label():
    return f"Current Progress: {pb['value']}%"


def progress(data_read, all_data):
    if pb['value'] < 100:
        # pb['value'] += 20
        pb['value'] = data_read * 100 / all_data

        value_label['text'] = update_progress_label()
    else:
        showinfo(message='The progress completed!')


tk_bar_name = tkinter.Label(tk_window, text='Progress Bar:')
tk_bar_name.pack()

# progressbar
pb = ttk.Progressbar(
    tk_window,
    orient='horizontal',
    mode='determinate',
    length=280
)
# place the progressbar
# pb.grid(column=0, row=0, columnspan=2, padx=10, pady=20)
pb.pack()

tk_progress_value = ttk.Label(tk_window, text=progress)
tk_progress_value.pack()

# label
value_label = ttk.Label(tk_window, text=update_progress_label)
# value_label.grid(column=0, row=1, columnspan=2)
value_label.pack()

tk_window.mainloop()
