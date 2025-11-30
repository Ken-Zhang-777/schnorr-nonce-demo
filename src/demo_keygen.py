# src/demo_keygen.py
"""
demo_keygen.py
---------------
Demonstration script for key generation.
Generates a random private key and prints both private and public key in hex format.
"""

from key_utils import generate_privkey, privkey_to_pubkey


def main():
    # Generate private key
    priv = generate_privkey()

    # Derive public key
    pub = privkey_to_pubkey(priv)

    # Print results in hexadecimal form
    print("Private key (hex):", priv.hex())
    print("Public key (hex):", pub.hex())


if __name__ == "__main__":
    main()
