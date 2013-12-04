============
simplecrypto
============

Cryptographic library with really simple API.

Includes functions for hashes, symmetric and assymetric crypto, along with helper functions.


Hashes
------

::

  from simplecrypto import md5, sha1, hash

  md5('The quick brown fox jumps over the lazy dog')
  # '9e107d9d372bb6826bd81d3542a419d6'

  sha1('The quick brown fox jumps over the lazy dog')
  # '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'

  # 'hash' defaults to SHA1
  hash('message')
  # '6f9b9af3cd6e8b8a73c2cdced37fe9f59226e27d'


Symmetric crypto
----------------

::

  from simplecrypto import encrypt, decrypt, AesKey

  # `encrypt` and `decrypt` use AES-256.

  m = encrypt('secret message', 'secret key')
  decrypt(m, 'secret key')
  # b'secret message'

  # Generates a new AES-256 random key.
  key = AesKey()
  m = key.encrypt('secret message')
  key.decrypt(m)
  # b'secret message'

  key = AesKey('secret key') # key from string
  key = AesKey(random(32)) # key from bytes


Asymmetric crypto
-----------------

::

  from simplecrypto import RsaKeypair, RsaPublicKey

  skey = RsaKeypair(2048)
  pkey = skey.publickey

  m = pkey.encrypt('secret message')
  skey.decrypt(m)
  # b'secret message'

  s = skey.sign('authenticated message')
  pkey.verify('authenticated message', s)
  # True

  # Long messages are encrypted with a random AES-256 key for performance.
  m = pkey.encrypt('long message ' * 100)
  skey.decrypt(m)
  # b'long message long message long message...'


Protocol helpers
----------------

::

  from simplecrypto import RsaKeypair
  from simplecrypto import send, receive

  alice = RsaKeypair()
  bob = RsaKeypair()
  charlie = RsaKeypair()

  # Prepares a message from Alice to Bob and Charlie.
  # The message is signed and encrypted.
  m = send('secret message', alice, bob, charlie)

  # Bob opens the message from Alice.
  receive(m, bob, alice)
  # b'secret message'

  # Charlie opens the message from Alice.
  receive(m, charlie, alice)
  # b'secret message'

  # Eve tries to eavesdrop.
  eve = RsaKeypair()
  receive(m, eve, alice)
  # EncryptionError!


And miscellaneous helpers
------------------------

::

  import simplecrypto

  simplecrypto.base64('message')
  # 'bWVzc2FnZQ=='

  simplecrytpo.from_hex('FF')
  # b'\xff'

  simplecrypto.pad('short', 10, '.')
  # b'short.....'

  random(5)
  # b'A\xd5\x12\x054'    five random bytes
