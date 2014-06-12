============
simplecrypto
============

.. image:: https://travis-ci.org/boppreh/simplecrypto.png?branch=master
    :target: https://travis-ci.org/boppreh/simplecrypto

.. image:: https://coveralls.io/repos/boppreh/simplecrypto/badge.png
    :target: https://coveralls.io/r/boppreh/simplecrypto 

.. image:: https://badge.fury.io/py/simplecrypto.png
    :target: https://pypi.python.org/pypi/simplecrypto/

Cryptographic library with really simple API.

Includes functions for hashes, symmetric and asymmetric crypto, along with
helper functions. Acts as a wrapper for ``PyCrypto`` and a few standard
libraries.


Documentation
-------------

Documentation is available at http://simplecrypto.readthedocs.org.

The full source code repository is at https://github.com/boppreh/simplecrypto.


Installation
------------

::

  pip install simplecrypto

This library depends on ``PyCrypto``. On Linux this is installed automatically by
pip. If the dependency installation fail on Windows, you may want to 
use a `prebuilt installer <http://www.voidspace.org.uk/python/modules.shtml#pycrypto>`_.
If you wish to compile it I suggest using the Mingw tools `as indicated
here <http://stackoverflow.com/a/5051281/252218>`_.


Usage
-----

::

  from simplecrypto import sha1, encrypt, decrypt, RsaKeypair, base64

  sha1('The quick brown fox jumps over the lazy dog')
  # '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'

  # `encrypt` and `decrypt` use AES-256.
  m = encrypt('secret message', 'secret key')
  print(m)
  # 'uRKa9xX7zW6QT1yJxIQb5E/0DzaxQglVggnFam5K'
  decrypt(m, 'secret key')
  # b'secret message'

  skey = RsaKeypair(2048)
  pkey = skey.publickey

  m = pkey.encrypt('secret message')
  skey.decrypt(m)
  # b'secret message'

  s = skey.sign('authenticated message')
  pkey.verify('authenticated message', s)
  # True

  base64('message')
  # 'bWVzc2FnZQ=='
