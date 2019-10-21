from pyDes import *

data = "123456"
k = des("00000000", CBC, IV='\0\0\0\0\0\0\0\0', pad=None, padmode=PAD_PKCS5)
d = k.encrypt(data)
print(d.hex())
# bytes.decode(d)
print(type(d))
print("Encrypted 16: %r" % d.hex())
print("Encrypted: %r" % d)
print("Decrypted: %r" % bytes.decode(k.decrypt(d)))
assert bytes.decode(k.decrypt(d)) == data
