"""
Module for retrieving cryptographically random values.
"""

from Crypto import Random

_random_instance = Random.new()

def random(n_bytes):
    """
    Returns `n_bytes` of cryptographically secure random bytes.
    """
    return _random_instance.read(n_bytes)
