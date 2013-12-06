"""
Module for reverse engineering crypto protocols.
"""
from os import path

from .hashes import *
from .formats import *

def _append_newline(s):
    return s + '\n'

def _replace_backslashes(s):
    return s.replace('\\', '/')


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

def guess_transformation(message, hash_value):
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
