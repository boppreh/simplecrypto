import hashlib
import math
from os import path
from base64 import b64encode, b64decode
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

hashes = [sha1, md5, sha256, sha512]


def str_to_base64(message):
    return b64encode(message)

def base64_to_str(message):
    return b64decode(message)

def str_to_hex(message):
    return message.encode('hex')

def hex_to_str(message):
    return message.decode('hex')

base64 = str_to_base64
hex = str_to_hex
encodes = [str_to_base64, str_to_hex]
modifiers = [str.lower, str.upper, str.strip, str.rstrip,
             path.basename, path.abspath, path.dirname, path.relpath,
             lambda s: s + '\n', lambda s: '/' + s,
             lambda s: s.replace('\\', '/'), lambda s: s.replace('-', '')]
decodes = [base64_to_str, hex_to_str]

def apply_modifiers(modifiers, message):
    try:
        for modifier in modifiers:
            message = modifier(message)
    finally:
        return message

def guess_hash(message, hash_value, cur_guess=[]):
    if len(cur_guess) > 4:
        return None

    if apply_modifiers(cur_guess, message) == hash_value:
        return cur_guess

    for modifier in hashes + modifiers + decodes:
        next_guess = cur_guess + [modifier]
        if guess_hash(message, hash_value, next_guess):
            return next_guess
        
    return None

print guess_hash('teste\n', sha1('teste'))


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

def encrypt_des(message, password):
    return encrypt(message, password, 'des')

def decrypt_des(message, password):
    return decrypt(message, password, 'des')
