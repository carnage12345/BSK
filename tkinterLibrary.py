from tkinter import filedialog
import time
from RSAKeysLibrary import encrypt, decrypt, sign_sha1, verify_sha1
import os


# Jaworski

def button_send_message(entry, client):
    message = entry.get()
    print(message)
    client.send("message".encode("utf8"))
    client.send(message.encode("utf8"))


def button_send_message_function_encoded(entry, client):
    message = entry.get()
    print(message)

    # ciphertext = encrypt(message, publicKey)
    # signature = sign_sha1(message, privateKey)

    client.send("message_encoded".encode("utf8"))
    client.send(message.encode("utf8"))


def encrypt_decrypt_message(publicKeyB, privateKeyB):
    message = "here i come"
    print(message)
    ciphertext = encrypt(message, publicKeyB)
    signature = sign_sha1(message, privateKeyB)
    plaintext = decrypt(ciphertext, privateKeyB)

    print(f"CipherText:{ciphertext}")
    print(f"Signature:{signature}")

    if plaintext:
        print(f"PlainText: {plaintext}")
    else:
        print("encryption-decryption failed")

    if verify_sha1(plaintext, signature, publicKeyB):
        print("signature verified")
    else:
        print("Could not verift the message signature")


def button_open_file_function(text_variable_label2):
    file_path = filedialog.askopenfilename(title="BSK - which file to open?",
                                           filetypes=(("txt files", "*.txt"),
                                                      ("all files", "*.*"),
                                                      ("png files", "*.png"),
                                                      ("pdf files", "*.pdf"),
                                                      ("avi files", "*.avi"),
                                                      ("jpg files", "*.jpg")))
    print(file_path)
    global file_path_test
    file_path_test = file_path
    text_variable_label2.set(file_path_test)


def button_send_file_function(client, BUFFER, progress):
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


# Żebrowski

def update_progress_label(pb):
    return f"Current Progress: {pb['value']}%"


def progress(pb, value_label, showinfo, data_read, all_data):
    if pb['value'] < 100:
        # pb['value'] += 20
        pb['value'] = data_read * 100 / all_data

        value_label['text'] = update_progress_label()
    else:
        showinfo(message='The progress completed!')
