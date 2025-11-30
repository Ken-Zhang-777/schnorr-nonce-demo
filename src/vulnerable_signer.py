import os
import sys

# add current folder to path so we can import sibling file
# python import system is headache sometimes...
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from schnorr_core import sign, N
from coincurve import PrivateKey

def run_vulnerable_scenario():
    print("--- STARTING VULNERABLE SIGNING SCENARIO ---")
    
    # 1. Setup the Victim (Alice)
    # just random private key
    alice_priv_bytes = os.urandom(32)
    alice_priv_int = int.from_bytes(alice_priv_bytes, 'big')
    
    # get pubkey for display
    alice_pub = PrivateKey(alice_priv_bytes).public_key.format(compressed=True)
    
    print(f"Victim Private Key (KEEP SECRET!!): {alice_priv_bytes.hex()}")
    print(f"Victim Public Key: {alice_pub.hex()}")
    print("-" * 20)

    # 2. THE FATAL MISTAKE!!!
    # Alice uses a FIXED nonce k for everything.
    # maybe she copy paste from stackoverflow?? who knows.
    BAD_K_VALUE = 0x1234567890deadbeef1234567890deadbeef1234567890deadbeef12345678
    
    # sanity check k is valid
    BAD_K_VALUE = BAD_K_VALUE % N
    print(f"FIXED NONCE k (Hidden): {hex(BAD_K_VALUE)}")
    print("-" * 20)

    # 3. Sign Message A
    msg1 = b"I love crypto"
    # force use BAD_K_VALUE
    (R1, s1) = sign(msg1, alice_priv_int, k_nonce_int=BAD_K_VALUE)
    
    print(f"Message 1: {msg1}")
    print(f"Signature 1 (R, s):")
    print(f"  R: {R1.hex()}")
    print(f"  s: {hex(s1)}")

    # 4. Sign Message B
    # Alice signs different message... BUT SAME K!!!!
    msg2 = b"I reuse nonces"
    (R2, s2) = sign(msg2, alice_priv_int, k_nonce_int=BAD_K_VALUE)

    print(f"\nMessage 2: {msg2}")
    print(f"Signature 2 (R, s):")
    print(f"  R: {R2.hex()}") 
    # R2 MUST BE SAME AS R1 because R = k*G and k is same!!!
    print(f"  s: {hex(s2)}")
    
    if R1 == R2:
        print("\n[!] DANGER: R values are IDENTICAL! Attack possible!")
    else:
        print("Wait... R values different? math broken??")

if __name__ == "__main__":
    run_vulnerable_scenario()