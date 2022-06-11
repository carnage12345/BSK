from tkinter import filedialog
from tkinter.messagebox import showinfo
import time

from Crypto.Cipher import AES

from RSAKeysLibrary import *
import os


def button_send_message(entry, client):
    message = entry.get()
    print(message)
    client.send("message".encode("utf8"))
    client.send(message.encode("utf8"))

def send_message_encoded_rsa(tk_entry_encoded, client, publicKey, privateKey):
    message = tk_entry_encoded.get()
    print(message)

    ciphertext = encrypt(message, publicKey)
    signature = sign_sha1(message, privateKey)

    client.send("message_encoded".encode("utf8"))
    client.send(ciphertext)


def send_message_encoded_cbc(tk_entry_CBC, sessionKey, pad, client):
    message = tk_entry_CBC.get()
    print(message)

    cipherCBC = AES.new(sessionKey, AES.MODE_CBC)  # wybor cbc albo ecb
    iVectorCBC = cipherCBC.iv
    ciphertextCBC = cipherCBC.encrypt(pad(message.encode("utf8"), AES.block_size))

    print(ciphertextCBC)

    client.send("message_encoded_cbc".encode("utf8"))
    client.send(iVectorCBC)  # czy wektor powinien byc zakodowany?
    client.send(ciphertextCBC)


def send_message_encoded_ebc(tk_entry_CBC, sessionKey):
    message = tk_entry_CBC.get()
    print(message)
    cipherECB = AES.new(sessionKey, AES.MODE_ECB)


def encrypt_decrypt_message(publicKey, privateKey):
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
        print("Could not verify the message signature")



def button_open_file_function(pathStringVar):
    path = filedialog.askopenfilename(title="BSK - which file to open?",
                                      filetypes=(("all files", "*.*"),
                                                 ("txt files", "*.txt"),
                                                 ("png files", "*.png"),
                                                 ("pdf files", "*.pdf"),
                                                 ("avi files", "*.avi"),
                                                 ("jpg files", "*.jpg")))
    print(path)
    pathStringVar.set(path)


def button_send_file_function(client, BUFFER, path, pb, pbValue, window):
    client.send("file".encode("utf8"))

    SEPARATOR = "<SEPARATOR>"
    # filePath = file_path_test
    filePath = path
    fileSize = os.path.getsize(filePath)

    client.send(f"{filePath}{SEPARATOR}{fileSize}".encode())

    print(filePath)

    print(str(fileSize), ' B, ', str(fileSize / 1024), ' KB, ', str(fileSize / 1048576), ' MB')
    with open(filePath, "rb") as f:
        sendDataSize = 0
        startTime = time.time()
        while sendDataSize < fileSize:
            data = f.read(BUFFER)
            if not data:
                break
            client.sendall(data)
            sendDataSize += len(data)
            # print(str(sendDataSize * 100 / fileSize) + ' %')
            # progress.update(len(bytes_read))
            # progress_bar(pb, pbValue, sendDataSize, fileSize)

            # Progress Bar
            if pb['value'] < 100:
                pb['value'] = int((sendDataSize * 100) / fileSize)
                pbValue['text'] = f"Current Progress: {pb['value']}%"  # update_progress_label(pb)

            window.update()

    endTime = time.time()
    showinfo(message='The progress completed!')
    pb['value'] = 0
    pbValue['text'] = f"Current Progress: 0%"
    print("File transfer complete:", endTime - startTime, " s")


def check_queue(q, control):
    if q.empty():
        print('queue is empty')
        control.set('nothing')
    else:
        print('queue is not empty')
        control.set(q.get())

def button_set_password(password_entry, letter):
    user_friendly_password = password_entry.get()
    encryptRSAKeysAndSave(letter, user_friendly_password)


