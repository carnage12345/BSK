from tkinter import filedialog
from tkinter.messagebox import showinfo
import time
from RSAKeysLibrary import encrypt, decrypt, sign_sha1, verify_sha1
import os


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


def button_open_file_function(path_string_var):
    path = filedialog.askopenfilename(title="BSK - which file to open?",
                                      filetypes=(("all files", "*.*"),
                                                 ("txt files", "*.txt"),
                                                 ("png files", "*.png"),
                                                 ("pdf files", "*.pdf"),
                                                 ("avi files", "*.avi"),
                                                 ("jpg files", "*.jpg")))
    print(path)
    path_string_var.set(path)


def button_send_file_function(client, BUFFER, path, pb, pb_value):
    client.send("file".encode("utf8"))

    SEPARATOR = "<SEPARATOR>"
    # filePath = file_path_test
    filePath = path
    fileSize = os.path.getsize(filePath)

    client.send(f"{filePath}{SEPARATOR}{fileSize}".encode())

    print(filePath)

    print(str(fileSize), ' B, ', str(fileSize/1024), ' KB, ', str(fileSize/1048576),  ' MB')
    with open(filePath, "rb") as f:
        sendDataSize = 0
        startTime = time.time()
        while sendDataSize < fileSize:
            data = f.read(BUFFER)
            if not data:
                break
            client.sendall(data)
            sendDataSize += len(data)
            print(str(sendDataSize * 100 / fileSize) + ' %')
            # progress.update(len(bytes_read))
            # progress_bar(pb, pb_value, sendDataSize, fileSize)

            # Progress Bar
            if pb['value'] < 100:
                pb['value'] = int(sendDataSize * 100 / fileSize)
                pb_value['text'] = f"Current Progress: {pb['value']}%"  # update_progress_label(pb)

    endTime = time.time()
    showinfo(message='The progress completed!')
    pb['value'] = 0
    pb_value['text'] = f"Current Progress: 0%"
    print("File transfer complete:", endTime - startTime, " s")