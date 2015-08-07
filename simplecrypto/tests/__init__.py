#! /usr/bin/env python
import sys
from os import path
project_root = path.join(path.abspath(__file__), '..', '..', '..')
sys.path.append(path.normpath(project_root))

import unittest
from simplecrypto import *
from simplecrypto.key import session_encrypt_raw, session_decrypt_raw, Key
from simplecrypto.guess import _append_newline, _replace_backslashes

class TestHashing(unittest.TestCase):
    def test_md5(self):
        self.assertEqual('9e107d9d372bb6826bd81d3542a419d6',
                         md5('The quick brown fox jumps over the lazy dog'))
        self.assertEqual('d41d8cd98f00b204e9800998ecf8427e', md5(''))
        self.assertEqual('d41d8cd98f00b204e9800998ecf8427e', md5(b''))

    def test_sha1(self):
        self.assertEqual('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
                         sha1('The quick brown fox jumps over the lazy dog'))
        self.assertEqual('da39a3ee5e6b4b0d3255bfef95601890afd80709', sha1(''))
        self.assertEqual('da39a3ee5e6b4b0d3255bfef95601890afd80709', sha1(b''))

    def test_sha256(self):
        self.assertEqual('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
                         sha256('The quick brown fox jumps over the lazy dog'))
        self.assertEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', sha256(''))
        self.assertEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', sha256(b''))

    def test_sha512(self):
        self.assertEqual('07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6',
                         sha512('The quick brown fox jumps over the lazy dog'))
        self.assertEqual('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', sha512(''))
        self.assertEqual('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', sha512(b''))

    def test_hmac(self):
        original = hmac('message', 'key')
        altered = hmac('message2', 'key')
        self.assertNotEqual(original, altered)

class TestConversion(unittest.TestCase):
    def test_base64(self):
        self.assertEqual('', to_base64(''))
        self.assertEqual('', to_base64(b''))
        self.assertEqual(b'', from_base64(''))
        self.assertEqual(b'', from_base64(b''))
        self.assertEqual(b'test', from_base64(to_base64('test')))
        self.assertEqual(b'test', from_base64(to_base64(b'test')))

    def test_hex(self):
        self.assertEqual('', to_hex(''))
        self.assertEqual('', to_hex(b''))
        self.assertEqual(b'', from_hex(''))
        self.assertEqual(b'', from_hex(b''))
        self.assertEqual(b'test', from_hex(to_hex('test')))
        self.assertEqual(b'test', from_hex(to_hex(b'test')))

    def test_str(self):
        self.assertEqual('test', to_str('test'))
        self.assertEqual('test', to_str(b'test'))

    def test_bytes(self):
        self.assertEqual(b'test', to_bytes('test'))
        self.assertEqual(b'test', to_bytes(b'test'))

class TestSymmetric(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(b'test', decrypt(encrypt(b'test', b'pass'), b'pass'))
        self.assertEqual(b'test', decrypt(encrypt(b'test', 'pass'), 'pass'))
        self.assertEqual(b'test', decrypt(encrypt('test', b'pass'), b'pass'))
        self.assertEqual(b'test', decrypt(encrypt('test', 'pass'), 'pass'))

        self.assertNotEqual(b'test', decrypt(encrypt('test', 'pass'), 'passX'))

    def test_long_message(self):
        m = b'test' * 100
        self.assertEqual(m, decrypt(encrypt(m, 'pass'), 'pass'))

        self.assertNotEqual(m, decrypt(encrypt(m, 'pass'), 'passX'))

    def test_serialize(self):
        key = AesKey(b'pass')
        self.assertEqual(b'pass', key.serialize())
        self.assertEqual(key, AesKey(key.serialize()))

class TestAbstractKey(unittest.TestCase):
    def test_nbits(self):
        self.assertEqual(128, Key('', block_size=16).nbits)

    def test_block_size(self):
        self.assertEqual(16, Key('', nbits=128).block_size)

    def test_incomplete_constructor(self):
        with self.assertRaises(EncryptionError):
            Key('')

class TestAsymmetric(unittest.TestCase):
    def test_encrypt(self):
        rsa = RsaKeypair(1024)
        self.assertEqual(b'test', rsa.decrypt(rsa.encrypt(b'test')))
        self.assertEqual(b'test', rsa.decrypt(rsa.encrypt('test')))

    def test_sign(self):
        rsa = RsaKeypair(1024)
        self.assertTrue(rsa.verify(b'test', rsa.sign(b'test')))
        self.assertTrue(rsa.verify(b'test', rsa.sign('test')))
        self.assertTrue(rsa.verify('test', rsa.sign('test')))
        self.assertTrue(rsa.verify('test', rsa.sign(b'test')))

        self.assertFalse(rsa.verify('test', rsa.sign(b'testX')))

    def test_long_message(self):
        m = b'test' * 100
        rsa = RsaKeypair(1024)
        self.assertEqual(m, rsa.decrypt(rsa.encrypt(m)))

    def test_serialize(self):
        skey = RsaKeypair(1024)
        pkey = skey.publickey
        self.assertEqual(skey, RsaKeypair(skey.serialize()))
        self.assertEqual(pkey, RsaPublicKey(pkey.serialize()))

    def test_invalid_operation(self):
        with self.assertRaises(EncryptionError):
            RsaKeypair(1024).publickey.decrypt('')

class TestEncryptionProtocols(unittest.TestCase):
    def test_session(self):
        key = AesKey()
        encrypted = session_encrypt_raw(b'test', key)
        decrypted = session_decrypt_raw(encrypted, key)
        self.assertEqual(b'test', decrypted)

    def test_simple_send(self):
        sender = RsaKeypair(1024)
        receiver1 = RsaKeypair(1024)
        encrypted_message = send('test', sender, receiver1)
        self.assertEqual(b'test', receive(encrypted_message, receiver1, sender))

    def test_multiple_send(self):
        sender = RsaKeypair(1024)
        receiver1 = RsaKeypair(1024)
        receiver2 = RsaKeypair(1024)
        encrypted_message = send('test', sender, receiver1, receiver2)
        self.assertEqual(b'test', receive(encrypted_message, receiver1, sender))
        self.assertEqual(b'test', receive(encrypted_message, receiver2, sender))

    def test_different_sized_send(self):
        sender = RsaKeypair(2048)
        receiver1 = RsaKeypair(1024)
        receiver2 = RsaKeypair(1024)
        encrypted_message = send('test', sender, receiver1, receiver2)
        self.assertEqual(b'test', receive(encrypted_message, receiver1, sender))
        self.assertEqual(b'test', receive(encrypted_message, receiver2, sender))

    def test_invalid_receiver(self):
        sender = RsaKeypair(1024)
        receiver = RsaKeypair(1024)
        eve = RsaKeypair(1024)
        encrypted_message = send('test', sender, receiver)
        with self.assertRaises(EncryptionError):
            receive(encrypted_message, eve, sender)

    def test_tampering_send(self):
        sender = RsaKeypair(1024)
        receiver = RsaKeypair(1024)
        encrypted_message = send('test', sender, receiver)
        with self.assertRaises(EncryptionError):
            receive(encrypted_message[:-1], receiver, sender)

class TestGuess(unittest.TestCase):
    def test_single_hash(self):
        m = 'message'
        h = md5(m)
        self.assertEqual([md5], guess_transformation(m, h))

    def test_formatted_hash(self):
        m = 'message'
        h = md5(m) + '\n'
        self.assertEqual([md5, _append_newline], guess_transformation(m, h))

    def test_path(self):
        m = 'C:\\Users\\'
        h = m.replace('\\', '/')
        self.assertEqual([_replace_backslashes], guess_transformation(m, h))


if __name__ == '__main__':
    unittest.main()
