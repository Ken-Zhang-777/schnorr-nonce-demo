# src/key_utils.py
"""
key_utils.py
-------------
Utility functions for secp256k1 key generation and public key derivation.
This module provides basic helpers that will be reused by later scripts.
"""

from coincurve import PrivateKey


def generate_privkey():
    """
    Generate a random secp256k1 private key.

    Returns:
        bytes: 32-byte private key.
    """
    return PrivateKey().secret


def privkey_to_pubkey(priv_bytes, compressed=True):
    """
    Derive the corresponding public key from a given private key.

    Args:
        priv_bytes (bytes): 32-byte private key.
        compressed (bool): Whether to return compressed public key format (default True).

    Returns:
        bytes: Public key bytes (33 bytes if compressed).
    """
    return PrivateKey(priv_bytes).public_key.format(compressed=compressed)
