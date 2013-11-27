import hashlib
import math
from os import path
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from Crypto.Cipher import DES, AES
from Crypto.PublicKey import RSA as _RSA
from Crypto import Random

_random_instance = Random.new()

def md5(message):
    """
    Returns the hexadecimal representation of the MD5 hash digest.
    """
    return hashlib.md5(to_bytes(message)).hexdigest()

def sha1(message):
    """
    Returns the hexadecimal representation of the SHA1 hash digest.
    """
    return hashlib.sha1(to_bytes(message)).hexdigest()

def sha256(message):
    """
    Returns the hexadecimal representation of the SHA256 hash digest.
    """
    return hashlib.sha256(to_bytes(message)).hexdigest()

def sha512(message):
    """
    Returns the hexadecimal representation of the SHA512 hash digest.
    """
    return hashlib.sha512(to_bytes(message)).hexdigest()

# Available hash functions.
hashes = [sha1, md5, sha256, sha512]

# Default hash function.
hash = sha1


def to_base64(message):
    """
    Returns the base64 representation of a string or bytes.
    """
    return b64encode(to_bytes(message)).decode('ascii')

def from_base64(message):
    """
    Returns the bytes from a base64 representation.
    """
    return b64decode(to_bytes(message))

def to_hex(message):
    """
    Returns the (string) hexadecimal representation of a string or bytes.
    """
    return hexlify(to_bytes(message))

def from_hex(message):
    """
    Returns the bytes from a (string) hexadecimal representation.
    """
    return unhexlify(message)

def to_bytes(message):
    """
    Returns the bytes representation of an arbitrary message.
    """
    if isinstance(message, str):
        return message.encode('utf-8')
    else:
        return bytes(message)

def to_str(message):
    """
    Returns the string representation of an arbitrary message.
    """
    if isinstance(message, str):
        return message
    else:
        return message.decode('utf-8')

def _append_newline(s):
    return s + '\n'

def _replace_backslashes(s):
    return s.replace('\\', '/')

# Shorthands.
base64 = to_base64
hex = to_hex

_encodes = [to_base64, to_hex]
_modifiers = [str.lower, str.upper, str.strip,
             _append_newline, _replace_backslashes,
             path.basename, path.abspath, path.dirname]
_decodes = [from_base64, from_hex]

def _apply_modifiers(_modifiers, message):
    try:
        for modifier in _modifiers:
            message = modifier(message)
    finally:
        return message

def guess_hash(message, hash_value):
    """
    Given a `message` and its known value, returns the list of hash or modifiers
    functions applied to the message to arrive at the given `hash_value`.

    Useful for reverse engineering protocols or stored values.
    """
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


def pad(message, length, padding=b'0'):
    """
    Pads a message with binary zeroes until a given length is reached.
    """
    message = to_bytes(message)
    return message + (length - len(message)) * padding

def pad_multiple(message, len_multiple, padding=b'0'):
    """
    Pads a message with binary zeroes until the length is a desired multiple.
    """
    next_length = math.ceil(len(message) / float(len_multiple)) * len_multiple
    return pad(message, int(next_length), padding)

def random(n_bytes):
    """
    Returns `n_bytes` of cryptographically secure random bytes.
    """
    return _random_instance.read(n_bytes)

def encrypt(message, password):
    """
    Encrypt a `message` with a shared `password`.
    """
    iv = random(AES.block_size)
    instance = AES.new(pad_multiple(password, 16),
                       AES.MODE_CFB,
                       iv)
    return to_base64(iv + instance.encrypt(message))

def decrypt(message, password):
    """
    Decrypt an encrypted `message` with a shared `password`.
    """
    message = from_base64(message)
    iv, message = message[:AES.block_size], message[AES.block_size:]
    instance = AES.new(pad_multiple(password, 16),
                       AES.MODE_CFB,
                       iv)
    return instance.decrypt(message)

class Rsa(object):
    def __init__(self, rsa):
        self.rsa = rsa
        self.publickey = rsa.publickey()

    def encrypt(self, message):
        """
        Encrypts the given `message` with the public key.
        """
        return self.publickey.encrypt(to_bytes(message), _random_instance.read(1))

    def decrypt(self, message):
        """
        Decrypts the given `message` with the private key.
        """
        return self.rsa.decrypt(message)

    def sign(self, message):
        """
        Returns the signature of a given `message`, made with the private key.
        """
        return self.rsa.sign(from_hex(hash(message)), b'')

    def verify(self, message, signature):
        """
        Verifies if a given `message` matches the given `signature`.
        """
        return self.rsa.verify(from_hex(hash(message)), signature)

    def verify_hash(self, message_hash, signature):
        """
        Verifies if a given `message_hash` matches the given `signature`.
        """
        return self.rsa.verify(message_hash, signature)

def generate_keypair(nbits=2048):
    """
    Generates a new RSA keypair.
    """
    return Rsa(_RSA.generate(nbits, _random_instance.read))
