from tkinter import *
import tkinter as tk

window = tk.Tk()
window.title('Client ')

tk.Label(window, text='Enter your user-friendly password:').pack()
password_entry = tk.Entry(window)
password_entry.pack()
var = 0


def get_password():
    global var
    var = password_entry.get()
    # with open('./PasswordA/passA.txt', 'wb') as f:
    #     f.write(var)

def printing():
    print(var)

tk.Button(window, text="Set password",
                                   command=lambda: get_password()).pack()

tk.Button(window, text="Print variable",
                                   command=lambda: printing()).pack()


window.mainloop()


