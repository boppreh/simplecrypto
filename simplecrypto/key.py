"""
Module for cryptographic keys in general.
"""
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA as _RSA
from Crypto.Hash import SHA256
import struct
import math

from .random import random
from .formats import to_bytes, base64, from_base64, pad_multiple
from .exceptions import EncryptionError
from .hashes import hash

class Key(object):
    """
    Abstract base class for all keys, symmetric or not, public or not.

    Subclasses should implement `encrypt_raw`, `decrypt_raw` and `serialize`
    as necessary.
    """
    def __init__(self, algorithm_name, nbits=None, block_size=None):
        """
        Instantiates a new Key object. Algorithm name is a short string (ex
        'RSA') and caller must specify at least one of `nbits` or `block_size`,
        where `block_size` is measured in bytes.
        """
        if nbits is None and block_size is not None:
            nbits = block_size * 8
        elif block_size is None and nbits is not None:
            # Round number of bits to next power of 2.
            nbits = 2 ** math.ceil(math.log(nbits, 2))
            block_size = nbits // 8
        else:
            raise EncryptionError('Must specify `nbits` or `block_size`.')

        self.algorithm_name = algorithm_name
        self.algorithm = '{}-{}'.format(algorithm_name, nbits)
        self.block_size = int(block_size) 
        self.nbits = nbits

    def encrypt_raw(self, message):
        """
        Encrypts the given message. `message` must be of type `bytes` and the
        return is also raw bytes.
        """
        raise NotImplementedError('This is just an abstract Key class.')

    def decrypt_raw(self, encrypted_message):
        """
        Decrypts the given message. `encrypted_message` must be of type `bytes`
        and the return is also raw bytes.
        """
        raise NotImplementedError('This is just an abstract Key class.')

    def encrypt(self, message):
        """
        Encrypts the given message, first converting it to raw bytes. Returns
        the base64 encoded encrypted message.
        """
        return base64(self.encrypt_raw(to_bytes(message)))

    def decrypt(self, encrypted_message):
        """
        Decrypts the given encrypted message, converting it to bytes as
        required. Returns the message's bytes.
        """
        return self.decrypt_raw(from_base64(encrypted_message))

    def serialize(self):
        """
        Returns a `bytes` object representing this key.
        """
        raise NotImplementedError()

    def __repr__(self):
        try:
            return '<{} {}>'.format(type(self).__name__, hash(self.serialize()))
        except NotImplementedError:
            return object.__str__(self)

    def __eq__(self, other):
        return self.serialize() == other.serialize()


class AesKey(Key):
    """
    Class for symmetric AES with 256 bits block size.
    """
    def __init__(self, key=None):
        Key.__init__(self, 'AES', nbits=256)
        self.key = key or random(self.block_size)

    def encrypt_raw(self, message):
        iv = random(AES.block_size)
        instance = AES.new(pad_multiple(self.key, 16),
                           AES.MODE_CFB,
                           iv)
        return iv + instance.encrypt(message)

    def decrypt_raw(self, encrypted_message):
        iv = encrypted_message[:AES.block_size]
        message = encrypted_message[AES.block_size:]
        instance = AES.new(pad_multiple(self.key, 16),
                           AES.MODE_CFB,
                           iv)
        return instance.decrypt(message)

    def serialize(self):
        return self.key


class RsaPublicKey(Key):
    """
    Class for asymmetric public RSA key.
    """
    def __init__(self, key):
        if type(key) in [str, bytes]:
            key = _RSA.importKey(key)
        self.rsa = key

        Key.__init__(self, 'RSA', nbits=self.rsa.size())

        self.oaep = PKCS1_OAEP.new(self.rsa, hashAlgo=SHA256)
        self.pss = PKCS1_PSS.new(self.rsa)

    def encrypt_raw(self, message):
        if len(message) <= self.block_size + AES.block_size * 2:
            return self.oaep.encrypt(message)
        else:
            return session_encrypt_raw(message, self)

    def decrypt_raw(self, encrypted_message):
        raise EncryptionError('RSA public keys are unable to decrypt messages.')

    def verify(self, message, signature):
        h = SHA256.new()
        h.update(to_bytes(message))
        return self.pss.verify(h, signature)

    def serialize(self):
        return self.rsa.exportKey()


class RsaKeypair(Key):
    """
    Class for asymmetric RSA keypair.
    """
    def __init__(self, source=2048, prng=random):
        """
        Creates a new RSA keypair. Source may either be the serialized bytes or
        the number of desired bits. If source is the number of desired bits,
        prng can be specified.
        """
        if type(source) is int:
            self.rsa = _RSA.generate(source, prng)
        elif type(source) in [str, bytes]:
            self.rsa = _RSA.importKey(source)

        Key.__init__(self, 'RSA', nbits=self.rsa.size())

        self.oaep = PKCS1_OAEP.new(self.rsa, hashAlgo=SHA256)
        self.pss = PKCS1_PSS.new(self.rsa)
        self.publickey = RsaPublicKey(self.rsa.publickey())

    def encrypt_raw(self, message):
        # Delegate to public key.
        return self.publickey.encrypt_raw(message)

    def decrypt_raw(self, message):
        if len(message) <= self.block_size + AES.block_size * 2:
            return self.oaep.decrypt(message)
        else:
            return session_decrypt_raw(message, self)

    def verify(self, message, signature):
        # Delegate to public key.
        return self.publickey.verify(message, signature)

    def sign(self, message):
        h = SHA256.new()
        h.update(to_bytes(message))
        return self.pss.sign(h)

    def serialize(self):
        return self.rsa.exportKey()


def encrypt(message, key):
    """
    Shortcut for AES256 base64 encryption with string or bytes key.
    """
    return AesKey(to_bytes(key)).encrypt(message)

def decrypt(encrypted_message, key):
    """
    Shortcut for AES256 base64 decryption with string or bytes key.
    """
    return AesKey(to_bytes(key)).decrypt(encrypted_message)

def session_encrypt_raw(message, destination_key):
    """
    Encrypts the message with a random session key, and protects this session
    key by encrypting with the destination key.

    Superior alternative when the destination key is slow (ex RSA).
    """
    session_key_bytes = random(AES.block_size)
    session_key = AesKey(session_key_bytes)

    encrypted_message = session_key.encrypt_raw(message)
    encrypted_session_key = destination_key.encrypt_raw(session_key_bytes)
    return encrypted_session_key + encrypted_message

def session_decrypt_raw(encrypted_message, destination_key):
    """
    Decrypts the message from a random session key, encrypted with the
    destination key.

    Superior alternative when the destination key is slow (ex RSA).
    """
    block_size = destination_key.block_size
    encrypted_session_key = encrypted_message[:block_size]
    message = encrypted_message[block_size:]
    session_key = AesKey(destination_key.decrypt_raw(encrypted_session_key))
    return session_key.decrypt_raw(message)

def send(message, sender_key, *recipient_keys):
    """
    Sends a secure message to one or more recipients. The message is encrypted
    with the recipient's key (so only they can read it), and signed with the
    sender's key (so the recipient can check the authenticity and integrity).

    Returns the binary payload.
    """
    message = to_bytes(message)

    signature = sender_key.sign(message)
    session_key_bytes = random(AES.block_size)
    session_key = AesKey(session_key_bytes)

    payload = [struct.pack('I', len(recipient_keys))]
    for recipient_key in recipient_keys:
        encrypted_session_key = recipient_key.encrypt_raw(session_key_bytes)
        payload.append(encrypted_session_key)
    payload.append(session_key.encrypt_raw(signature + message))
    return b''.join(payload)

def receive(payload, recipient_key, sender_key):
    """
    Receives a secure message from a binary payload.
    """
    n_recipients = struct.unpack('I', payload[:4])[0]
    end_of_session_keys = 4 + n_recipients * recipient_key.block_size
    end_of_signature = end_of_session_keys + sender_key.block_size
    encrypted_session_keys = payload[4:end_of_session_keys]

    session_key = None
    for i in range(n_recipients):
        start = i * recipient_key.block_size
        end = start + recipient_key.block_size

        encrypted_session_key = encrypted_session_keys[start:end]
        try:
            session_key_bytes = recipient_key.decrypt_raw(encrypted_session_key)
        except ValueError:
            continue
        session_key = AesKey(session_key_bytes)

    if session_key is None:
        raise EncryptionError('Unexpected recipient (no respective key found).')
    decrypted_message = session_key.decrypt_raw(payload[end_of_session_keys:])

    signature = decrypted_message[:sender_key.block_size]
    message = decrypted_message[sender_key.block_size:]
    if not sender_key.verify(message, signature):
        raise EncryptionError('Message signature doesn\'t match.')
    return message
