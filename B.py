import socket
from tkinterLibrary import *
from RSAKeysLibrary import generate_keys, load_keys

from Threads.ReceiveThread import ReceiveThread
from Threads.GUIThread import GUIThread


if __name__ == "__main__":
    # Keys
    generate_keys('B')
    publicKeyB, privateKeyB = load_keys('B')
    print("Keys Generated")

    # Keys test
    # encrypt_decrypt_message(publicKeyB, privateKeyB)

    #  Sockets
    receiveHOST = '127.0.0.1'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    receivePORT = 8888
    receiveBUFFER = 4194304  # 2097152 # 1048576   # 1024

    socketReceiveB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

    sendHOST = '192.168.1.12'  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
    sendPORT = 8888
    sendBUFFER = 4194304  # 2097152 # 1048576   # 1024

    socketSendB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

    # Create threads
    receivingThreadB = ReceiveThread(1, 'B', socketReceiveB, receiveHOST, receivePORT, receiveBUFFER, os)
    GUIThreadB = GUIThread(2, 'B', socketSendB, sendHOST, sendPORT, sendBUFFER) #  threadID, name, socket, HOST, PORT, BUFFER)

    # Start threads
    receivingThreadB.start()
    GUIThreadB.start()


    """"
    #  tk
    
    socketB.connect((HOST, PORT))  # CONNECT TO SERVER

    #  SEND NAME TO SERVER
    name = "bolek".encode("utf8")  # input('Twoje imie: ').encode("utf8")
    socketB.send(name)
    print(socketB.recv(BUFFER).decode("utf8"))
    
    
    window = tk.Tk()
    window.title('Client B')
    window.geometry('300x500')

    #  GLOBALS FOR tk #
    path_string_var = tk.StringVar()
    path_string_var.set("path to the file we are sending")


    #  tk MAIN PROGRAM

    title = tk.Label(window, text='BSK Project').pack()
    message = tk.Label(window, text='Message:').pack()
    entry = tk.Entry(window)
    entry.pack()
    sendButton = tk.Button(window, text='send message', command=lambda: button_send_message(entry, socketB)).pack()
    path_label = tk.Label(window, textvariable=path_string_var).pack()

    # pb = Progress Bar
    pb_label = tk.Label(window, text='Progress Bar:')  # .grid(column=0, row=3, padx=10, pady=10, sticky=tk.E)
    pb_label.pack()
    pb = ttk.Progressbar(window, orient='horizontal', mode='determinate',
                         length=280)  # .grid(column=0, row=4, padx=10, pady=10, sticky=tk.E)
    pb.pack()
    pb_value = ttk.Label(window, text="Current Progress: 0%")  # .grid(column=0, row=5, padx=10, pady=10, sticky=tk.E)
    pb_value.pack()

    fileOpenButton = tk.Button(window, text='file dialog',
                               command=lambda: button_open_file_function(path_string_var)).pack()
    fileSendButton = tk.Button(window, text='send file',
                               command=lambda: button_send_file_function(socketB, BUFFER, path_string_var.get(), pb,
                                                                         pb_value)).pack()

    window.mainloop()
"""""