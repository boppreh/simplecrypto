import hashlib
import math
import base64
from Crypto.Cipher import DES, AES
from Crypto import Random

random_instance = Random.new()

algorithms = {'aes': AES, 'des': DES}

def sha1(message):
    return hashlib.sha1(message).hexdigest()

def md5(message):
    return hashlib.md5(message).hexdigest()

def sha256(message):
    return hashlib.sha256(message).hexdigest()

def sha512(message):
    return hashlib.sha152(message).hexdigest()

def str_to_base64(message):
    return base64.b64encode(message)

def base64_to_str(message):
    return base64.b64decode(message)

def pad(message, length, padding=' '):
    return message + (length - len(message)) * padding

def pad_multiple(message, len_multiple, padding=' '):
    next_length = math.ceil(len(message) / float(len_multiple)) * len_multiple
    return pad(message, int(next_length), padding)

def random(n_bytes):
    return random_instance.read(n_bytes)

def encrypt(message, password, algorithm='aes'):
    cls = algorithms[algorithm]
    iv = random(cls.block_size)
    instance = cls.new(pad_multiple(password, 16),
                       cls.MODE_CFB,
                       iv)
    return str_to_base64(iv + instance.encrypt(message))

def decrypt(message, password, algorithm='aes'):
    message = base64_to_str(message)
    iv, message = message[:AES.block_size], message[AES.block_size:]
    instance = AES.new(pad_multiple(password, 16),
                       AES.MODE_CFB,
                       iv)
    return instance.decrypt(message)

def encrypt_aes(message, password):
    return encrypt(message, password, 'aes')

def decrypt_aes(message, password):
    return decrypt(message, password, 'aes')
