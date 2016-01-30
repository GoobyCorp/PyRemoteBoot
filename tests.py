import hashlib

from Crypto.Cipher import AES

bs = 32
key = hashlib.sha256("spinspinspin").digest()
iv = "a" * 16

print len(key)

pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
cipher = AES.new(key, AES.MODE_CBC, IV=iv)
print cipher.encrypt(pad("testing"))
