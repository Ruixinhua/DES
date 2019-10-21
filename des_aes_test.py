"""
This script is used to test the performance between DES and AES.
The requirement library includes numpy, pycrypto, and matplotlib
"""
import os
import time
import numpy as np
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Cipher import DES

from des_algorithm import *  # import my des algorithm library


__author__ = "Liu Dairui"


def encryption(text, algorithm, mode):
    start_time = time.time()
    if algorithm == "DES":
        if mode == "ECB":
            # DES ECB mode encrypt data
            k = DES.new(des_key, DES.MODE_ECB)
            value = k.encrypt(pad_text(str2ascii(text)))
        else:
            # DES CBC mode encrypt data
            k = DES.new(des_key, DES.MODE_CBC, IV=IV)
            value = k.encrypt(pad_text(str2ascii(text)))
    else:
        if mode == "ECB":
            # AES ECB mode encrypt data
            k = AES.new(aes_key, AES.MODE_ECB)
            value = k.encrypt(pad_text_aes(str2ascii(text)))
        else:
            # AES CBC mode encrypt data
            k = AES.new(aes_key, AES.MODE_CBC, "This is an IV456")
            value = k.encrypt(pad_text_aes(str2ascii(text)))
    return value, time.time() - start_time


def decryption(text, algorithm, mode):
    # decrypt data using corresponding algorithm and mode
    start_time = time.time()
    if algorithm == "DES":
        if mode == "ECB":
            k = DES.new(des_key, DES.MODE_ECB)
            k.decrypt(text)
        else:
            k = DES.new(des_key, DES.MODE_CBC, IV=IV)
            k.decrypt(text)
    else:
        if mode == "ECB":
            k = AES.new(aes_key, AES.MODE_ECB)
            k.decrypt(text)
        else:
            k = AES.new(aes_key, AES.MODE_CBC, "This is an IV456")
            k.decrypt(text)
    return time.time() - start_time


def pad_text_aes(text):
    pad_len = 16 - (len(text) % 16)
    return text + bytes([pad_len]) * pad_len


def start(r, algorithm, mode):
    # calculate encryption and decryption time
    times_en, times_de = [], []
    for size in range(1, r, step):
        time_en, time_de = [], []
        # calculate 10 times and average the result
        for _ in range(10):
            data = generate_data(size)
            text, tmp = encryption(data, algorithm, mode)
            time_en.append(tmp)
            tmp = decryption(text, algorithm, mode)
            time_de.append(tmp)
            del data
        times_en.append(np.mean(time_en))
        times_de.append(np.mean(time_de))
        print("{} with {} deal with {}MB data cost: {}s.".format(algorithm, mode, size, times_en[-1] + times_de[-1]))
    print("{} with {} finished.".format(algorithm, mode))
    return times_en, times_de


def generate_data(size):
    return os.urandom(1024 * 1024 * size).hex()


if __name__ == "__main__":
    # the default algorithm and mode chosen here
    algorithms = ["DES", "AES"]
    modes = ["ECB", "CBC"]
    aes_key = "Sixteen byte key"
    des_key = "00000000"
    IV = "00000000"
    rounds, step = 102, 16
    fig_en = plt.figure()
    fig_de = plt.figure()
    ax_en = fig_en.add_subplot(111)
    ax_de = fig_de.add_subplot(111)
    for a in algorithms:
        for m in modes:
            t_e, t_d = start(rounds, a, m)
            ax_en.plot(range(1, rounds, step), t_e, marker='o', linestyle="--", linewidth=0.5,
                       label="{}+{}".format(a, m))
            ax_de.plot(range(1, rounds, step), t_d, marker='o', linestyle="--", linewidth=0.5,
                       label="{}+{}".format(a, m))
            del t_e, t_d
    ax_en.legend()
    ax_de.legend()
    plt.sca(ax_en)
    plt.title("Performance comparison between DES and AES: Encryption")
    plt.xlabel("Data Block size(MB)")
    plt.ylabel("Time(s)")
    plt.sca(ax_de)
    plt.title("Performance comparison between DES and AES: Decryption")
    plt.xlabel("Data Block size(MB)")
    plt.ylabel("Time(s)")
    fig_en.savefig("DESvsAES_encryption.png")
    fig_de.savefig("DESvsAES_decryption.png")
    plt.show()
