"""
Module for standard hash algorithms, always returning the hash in hexadecimal
string format.
"""
import hashlib
from Crypto.Hash import HMAC, SHA256
from .formats import to_bytes

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

def hmac(message, key):
    """
    Returns the Hash Message Authentication Code for a given message, providing
    integrity and authenticity assurances.
    """
    h = HMAC.new(to_bytes(key), to_bytes(message), digestmod=SHA256)
    return h.hexdigest()

# Available hash functions.
hashes = [sha1, md5, sha256, sha512]

# Default MAC algorithm.
mac = hmac

# Default hash function.
hash = sha256
