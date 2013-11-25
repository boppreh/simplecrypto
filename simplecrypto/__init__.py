import hashlib
import math
from os import path
from base64 import b64encode, b64decode
from Crypto.Cipher import DES, AES
from Crypto.PublicKey import RSA
from Crypto import Random

_random_instance = Random.new()

algorithms = {'aes': AES, 'des': DES}

def md5(message):
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.md5(message).hexdigest()

def sha1(message):
    return hashlib.sha1(message).hexdigest()

def sha256(message):
    return hashlib.sha256(message).hexdigest()

def sha512(message):
    return hashlib.sha512(message).hexdigest()

hashes = [sha1, md5, sha256, sha512]
hash = sha1


def str_to_base64(message):
    return b64encode(message)

def base64_to_str(message):
    return b64decode(message)

def str_to_hex(message):
    return message.encode('hex')

def hex_to_str(message):
    return message.decode('hex')

def append_newline(s):
    return s + '\n'

def replace_backslashes(s):
    return s.replace('\\', '/')

base64 = str_to_base64
hex = str_to_hex
_encodes = [str_to_base64, str_to_hex]
_modifiers = [str.lower, str.upper, str.strip,
             append_newline, replace_backslashes,
             path.basename, path.abspath, path.dirname]
_decodes = [base64_to_str, hex_to_str]

def _apply_modifiers(_modifiers, message):
    try:
        for modifier in _modifiers:
            message = modifier(message)
    finally:
        return message

def guess_hash(message, hash_value):
    from collections import deque
    guesses = deque()
    guesses.append([])
    while len(guesses):
        guess = guesses.popleft()
        if _apply_modifiers(guess, message) == hash_value:
            return guess

        if len(guess) < 5:
            for modifier in hashes + _modifiers + _decodes + _encodes:
                guesses.append(guess + [modifier])
    return None


def pad(message, length, padding=' '):
    return message + (length - len(message)) * padding

def pad_multiple(message, len_multiple, padding=' '):
    next_length = math.ceil(len(message) / float(len_multiple)) * len_multiple
    return pad(message, int(next_length), padding)

def random(n_bytes):
    return _random_instance.read(n_bytes)

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

class RsaWrapper(object):
    def __init__(self, rsa):
        self.rsa = rsa
        self.publickey = rsa.publickey()

    def encrypt(self, message):
        return self.publickey.encrypt(message, _random_instance.read(1))

    def decrypt(self, message):
        return self.rsa.decrypt(message)

    def sign(self, message):
        return self.rsa.sign(hash(message), '')

    def verify(self, message, signature):
        return self.rsa.verify(hash(message), signature)

    def verify_hash(self, message_hash, signature):
        return self.rsa.verify(message_hash, signature)

def generate_keypair(nbits=2048):
    return RsaWrapper(RSA.generate(nbits, _random_instance.read))

if __name__ == '__main__':
    p = random(32)
    print(decrypt(encrypt('asdf', p), p))
