.. simplecrypto documentation master file, created by
   sphinx-quickstart on Fri Dec  6 17:41:17 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

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

Includes functions for hashes, symmetric and asymmetric crypto, along with helper
functions. Acts as a wrapper for ``PyCrypto`` and a few standard libraries.

Installation
============

::

  pip install simplecrypto

This library depends on ``PyCrypto``. On Linux this is installed automatically by
pip. If the dependency installation fail on Windows, you may want to 
use a `prebuilt installer <http://www.voidspace.org.uk/python/modules.shtml#pycrypto>`_.


API Documentation
=================

.. toctree::
   :maxdepth: 2

   simplecrypto


Examples
========

.. toctree::
    :maxdepth: 2

    examples
