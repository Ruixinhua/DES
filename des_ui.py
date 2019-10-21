"""
This program is used to show the GUI of performance comparison
"""
from tkinter import *  # import tkinter library
from tkinter import messagebox
from tkinter import ttk
from tkinter.filedialog import askopenfilename
import time
import os
from des_algorithm import *  # import my des algorithm library
from Crypto.Cipher import AES
from Crypto.Cipher import DES


__author__ = "Liu Dairui"


def encryption():
    try:
        start_time = time.time()
        text = generated_data.get("1.0", END)
        print('encryption', text)
        if algorithm == "DES":
            if mode == "ECB":
                # DES ECB mode encrypt data
                k = DES.new(des_key, DES.MODE_ECB)
                value = k.encrypt(pad_text(str2ascii(text)))
                print('DES ECB', value)
            else:
                # DES CBC mode encrypt data
                k = DES.new(des_key, DES.MODE_CBC, IV=IV)
                value = k.encrypt(pad_text(str2ascii(text)))
                print('DES CBC', value)
        else:
            if mode == "ECB":
                k = AES.new(aes_key, AES.MODE_ECB)
                value = k.encrypt(pad_text_aes(str2ascii(text)))
                print('AES ECB', value)
            else:
                k = AES.new(aes_key, AES.MODE_CBC, "This is an IV456")
                value = k.encrypt(pad_text_aes(str2ascii(text)))
                print('AES CBC', value)
        # encrypt_value.set(value)
        encrypted_data.replace("1.0", END, value.hex())
        return time.time() - start_time
    except ValueError:
        messagebox.showinfo(title="Input error", message="Please input ascii unicode values")


def decryption():
    try:
        start_time = time.time()
        text = encrypted_data.get("1.0", END).strip()
        text = bytes.fromhex(text)
        print('decryption', text)
        if algorithm == "DES":
            if mode == "ECB":
                k = DES.new(des_key, DES.MODE_ECB)
                value = k.decrypt(text)
            else:
                k = DES.new(des_key, DES.MODE_CBC, IV=IV)
                value = k.decrypt(text)
        else:
            if mode == "ECB":
                k = AES.new(aes_key, AES.MODE_ECB)
                value = k.decrypt(unpad_text(text))
            else:
                k = AES.new(aes_key, AES.MODE_CBC, "This is an IV456")
                value = k.decrypt(unpad_text(text))
        decrypted_data.replace("1.0", END, value)
        return time.time() - start_time
    except ValueError:
        messagebox.showinfo(title="Input error", message="Invalid data length, data must be a multiple of 8 bytes\n.")
    except:
        messagebox.showinfo(title="Input is not formal", message="The code is not correct here")


def pad_text_aes(text):
    pad_len = 16 - (len(text) % 16)
    return text + bytes([pad_len]) * pad_len


def start():
    size = var_size.get()
    if size:
        generate_data()
    time_used = encryption()
    time_used += decryption()
    var_time.set("{:.2f}ms".format(time_used * 1000))
    print(time_used)


def select_file():
    file_name = askopenfilename()
    set_file(file_name)


def set_file(file_name):
    with open(file_name, "rb") as f:
        var_data.set(b"".join(f.readlines()))
        generated_data.replace("1.0", END, var_data.get())


def generate_data():
    size = var_size.get()
    local_time = time.strftime("%Y%m%d%H%M%S", time.localtime())
    file_name = str(local_time)+".txt"
    big_file = open(file_name, "w")
    big_file.write(os.urandom(1024*size).hex())
    big_file.close()
    set_file(file_name)
    os.remove(file_name)


def select_algorithm(*args):
    global algorithm
    algorithm = algorithm_list.get()


def select_mode(*args):
    global mode
    mode = encryption_mode.get()


if __name__ == "__main__":
    # the default algorithm and mode chosen here
    algorithm, mode = "DES", "ECB"
    aes_key = "Sixteen byte key"
    des_key = "00000000"
    IV = "00000000"
    root = Tk()
    var_data = StringVar()
    # set title
    root.title("DES vs AES demonstration")
    root.geometry("800x500")
    # generated data is shown here
    Label(root, text="Generated Data").place(x=80, y=10)
    generated_data = Text(root, bg="grey", height=20, width=30)
    generated_data.place(x=20, y=40)
    # encrypted data is shown here
    Label(root, text="Encrypted Data").place(x=350, y=10)
    encrypted_data = Text(root, bg="grey", height=20, width=30)
    encrypted_data.place(x=290, y=40)
    # decrypted data is shown here
    Label(root, text="Decrypted Data").place(x=610, y=10)
    decrypted_data = Text(root, bg="grey", height=20, width=30)
    decrypted_data.place(x=560, y=40)
    # the load size is shown here
    Label(root, text="Load:").place(x=20, y=380)
    var_size = IntVar()
    Entry(root, textvariable=var_size, width=5).place(x=60, y=380)
    Label(root, text="KB").place(x=120, y=380)
    Button(root, text="Generate", command=generate_data).place(x=160, y=380)
    # time used is shown here
    Label(root, text="Time Duration:").place(x=300, y=380)
    var_time = StringVar()
    Entry(root, textvariable=var_time, width=15).place(x=400, y=380)
    Button(root, text="Choose File", command=select_file).place(x=600, y=380)
    # choose one of algorithm from DES and AES
    Label(root, text="Encryption Algorithm:").place(x=20, y=420)
    algorithm_list = ttk.Combobox(root, width=5)
    algorithm_list["values"] = ["DES", "AES"]
    algorithm_list.current(0)
    algorithm_list.bind("<<ComboboxSelected>>", select_algorithm)
    algorithm_list.place(x=180, y=420)
    # choose one of mode from ECB and CBC
    Label(root, text="Encryption Mode:").place(x=300, y=420)
    encryption_mode = ttk.Combobox(root, width=5)
    encryption_mode["values"] = ["ECB", "CBC"]
    encryption_mode.current(0)
    encryption_mode.bind("<<ComboboxSelected>>", select_mode)
    encryption_mode.place(x=440, y=420)
    Button(root, text="Start", width=5, height=2, command=start).place(x=600, y=420)
    root.mainloop()
