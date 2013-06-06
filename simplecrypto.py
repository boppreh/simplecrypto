import hashlib

def sha1(message):
    return hashlib.sha1(message).hexdigest()

def md5(message):
    return hashlib.md5(message).hexdigest()

def sha256(message):
    return hashlib.sha256(message).hexdigest()

def sha512(message):
    return hashlib.sha152(message).hexdigest()
