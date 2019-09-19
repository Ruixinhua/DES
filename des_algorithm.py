def str2ascii(text: str):
    # Only accept byte strings or ascii unicode values, otherwise
    if isinstance(text, str):
        # Only accept ascii unicode values.
        try:
            return text.encode('ascii')
        except UnicodeEncodeError:
            pass
        raise ValueError("Please input ascii unicode values")
    return text


def str2bits(text):
    """Turn the string data, into a list of bits (1, 0)'s"""
    result = [0] * len(text) * 8
    pos = 0
    for ch in text:
        i = 7
        while i >= 0:
            if ch & (1 << i) != 0:
                result[pos] = 1
            else:
                result[pos] = 0
            pos += 1
            i -= 1
    return result


def bits2str(bits):
    """Turn the list of bits -> data, into a string"""
    result = []
    pos = 0
    c = 0
    while pos < len(bits):
        c += bits[pos] << (7 - (pos % 8))
        if (pos % 8) == 7:
            result.append(c)
            c = 0
        pos += 1
    return bytes(result)


def list_move(l, step):
    return l[step:] + l[:step]


def sub_key(key: list):

    key_results = []
    # permuted choice 1: convert 64-bit key to 56-bit key
    pc1 = [57, 49, 41, 33, 25, 17,  9,
           1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4]
    key1 = [key[i-1] for i in pc1]
    # permuted choice 2: convert 56-bit key to 48-bit key
    pc2 = [14, 17, 11, 24,  1, 5,
           3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8,
           16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32]
    Ci, Di = key1[:28], key1[28:]
    # iterate 16 times to produce keys
    for i in range(16):
        # default number of shifts is 2
        shifts = 2
        # if it is the 1st(index is 0), 2nd, 9th, and 16th, then change to 1
        if i in [0, 1, 8, 15]:
            shifts = 1
        # shift the list
        Ci, Di = list_move(Ci, shifts), list_move(Di, shifts)
        final = Ci + Di
        # add the key to the final list
        key_results.append([final[j-1] for j in pc2])
    return key_results


def s_replace(text: list):
    # s box replace
    text = [text[i*6:(i+1)*6] for i in range(int(len(text) / 6))]
    result = [0] * 32
    for i in range(8):
        # find the index of s box
        row = (text[i][0] << 1) + text[i][5]
        column = (text[i][1] << 3) + (text[i][2] << 2) + (text[i][3] << 1) + text[i][4]
        # find the value stored in the s box
        v = s_box[i][(row << 4) + column]
        for j in range(4):
            # convert 6 bits to 4 bits
            result[i*4+j] = (v & (2 ** (3 - j))) >> (3 - j)
    return result


def permutation(block, table):
    """
    permutation process: permutate value in block using the position provided by table
    :param block: the data waiting to permutation
    :param table: the permutation position
    :return: the result after permutated
    """
    return [block[i-1] for i in table]
    # return list(map(lambda x: block[x], table))


def xor(X, Y):
    return list(map(lambda x, y: x ^ y, X, Y))


def des_crypt(text: str, key: str, mode: bool):
    text = str2bits(text)
    keys = sub_key(str2bits(str2ascii(key)))
    # encryption
    text = permutation(text, ip)
    L, R = text[:32], text[32:]
    if mode:
        # if mode is 1 or true, then encryption the text
        iteration = 0
        iteration_adjustment = 1
    else:
        # if mode is 0 or false, then decryption the text
        iteration = 15
        iteration_adjustment = -1
    for i in range(16):
        tempR = R[:]
        # expansion
        R = permutation(R, expansion_table)
        # XOR with 48 bits key
        R = xor(R, keys[iteration])
        # s replace and p replace
        R = permutation(s_replace(R), p_table)
        # XOR with L[i-1
        R = xor(R, L)
        # L[i] becomes R[i-1]
        L = tempR
        iteration += iteration_adjustment
    # inverse initial permutation
    final = permutation(R + L, ip_)
    return final


def pad_text(text):
    pad_len = 8 - (len(text) % 8)
    return text + bytes([pad_len]) * pad_len


def unpad_text(text):
    pad_len = text[-1]
    return text[:-pad_len]


def crypt(text, key, mode):
    result = []
    length = len(text)
    for i in range(int(length / 8)):
        block = des_crypt(text[i*8:(i+1)*8], key, mode)
        result.append(bits2str(block))
    return bytes.fromhex('').join(result)


def encrypt(text, key):
    # change to ascii code
    text = str2ascii(text)
    # pad the text
    text = pad_text(text)
    # crypt the text
    return crypt(text, key, 1)


def decrypt(text, key):
    # change to ascii code
    text = str2ascii(text)
    text = crypt(text, key, 0)
    return unpad_text(text)


k = '12345678'
data = '123456fs'
tmp = encrypt(data, k)
d = bytes.decode(decrypt(tmp, '12345678'))
assert d == data
# print(bits2str(str2bits(str2ascii('123f'))))


# initial permutation table
ip = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]
# the inverse of the initial permutation
ip_ = [40, 8, 48, 16, 56, 24, 64, 32,
       39, 7, 47, 15, 55, 23, 63, 31,
       38, 6, 46, 14, 54, 22, 62, 30,
       37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28,
       35, 3, 43, 11, 51, 19, 59, 27,
       34, 2, 42, 10, 50, 18, 58, 26,
       33, 1, 41, 9, 49, 17, 57, 25]
# Expansion table for turning 32 bit blocks into 48 bits
expansion_table = [
    31, 0, 1, 2, 3, 4,
    3, 4, 5, 6, 7, 8,
    7, 8, 9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31, 0
]
# the 8 permutation boxes
s_box = [
    # S1
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

    # S2
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

    # S3
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

    # S4
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

    # S5
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

    # S6
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

    # S7
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

    # S8
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
# the p permutation table
p_table = [16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2, 8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25]