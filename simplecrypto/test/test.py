#! /usr/bin/env python
import sys
import os
sys.path.append(os.path.join('..', '..'))

import unittest
from simplecrypto import *

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
    def test_aes(self):
        self.assertEqual(b'test', decrypt(encrypt(b'test', b'pass'), b'pass'))
        self.assertEqual(b'test', decrypt(encrypt(b'test', 'pass'), 'pass'))
        self.assertEqual(b'test', decrypt(encrypt('test', b'pass'), b'pass'))
        self.assertEqual(b'test', decrypt(encrypt('test', 'pass'), 'pass'))

class TestAsymetric(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
