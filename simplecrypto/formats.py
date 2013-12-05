"""
Module for conversion between different formats, such as base64, hex, bytes and
utf-8.
"""
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
import math

def to_base64(message):
    """
    Returns the base64 representation of a string or bytes.
    """
    return b64encode(to_bytes(message)).decode('ascii')

def from_base64(message):
    """
    Returns the bytes from a base64 representation.
    """
    return b64decode(to_bytes(message), validate=True)

def to_hex(message):
    """
    Returns the (string) hexadecimal representation of a string or bytes.
    """
    return hexlify(to_bytes(message)).decode('ascii')

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

def pad(message, length, padding=b'\x00'):
    """
    Pads a message with binary zeroes until a given length is reached.
    """
    message = to_bytes(message)
    return message + (length - len(message)) * to_bytes(padding)

def pad_multiple(message, len_multiple, padding=b'\x00'):
    """
    Pads a message with binary zeroes until the length is a desired multiple.
    """
    next_length = math.ceil(len(message) / float(len_multiple)) * len_multiple
    return pad(message, int(next_length), padding)

# Shorthands.
base64 = to_base64
hex = to_hex
