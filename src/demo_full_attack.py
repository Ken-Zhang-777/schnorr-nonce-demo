import sys
import os

# setup path again... python path is pain in the ass
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from schnorr_core import sign, verify, q
from attack import recover_key
from coincurve import PrivateKey

def main():
    print("==================================================")
    print("   SCHNORR NONCE REUSE ATTACK - END TO END DEMO   ")
    print("==================================================")

    # --- STEP 1: ALICE SETUP ---
    print("\n[1] Alice generate her wallet...")
    alice_priv_bytes = os.urandom(32)
    alice_priv = int.from_bytes(alice_priv_bytes, 'big')
    
    # get pubkey bytes for verify later
    alice_pub_bytes = PrivateKey(alice_priv_bytes).public_key.format(compressed=True)
    alice_pub_hex = alice_pub_bytes.hex()
    
    print(f"    Alice Public Key: {alice_pub_hex}")
    print("    Alice Private Key: HIDDEN (we dont know yet!)")

    # --- STEP 2: ALICE MAKE MISTAKE ---
    print("\n[2] Alice sign two transaction with SAME y (oh no...)")
    
    # she use this y for everything... bad bad alice
    FIXED_Y = 0x4242424242424242424242424242424242424242424242424242424242424242
    
    msg1 = b"Transfer 1 BTC to Bob"
    msg2 = b"Transfer 5 BTC to Coffee Shop"
    
    print(f"    Signing msg1: {msg1}")
    (w1, z1) = sign(msg1, alice_priv, y_nonce_int=FIXED_Y)
    
    print(f"    Signing msg2: {msg2}")
    (w2, z2) = sign(msg2, alice_priv, y_nonce_int=FIXED_Y)
    
    # convert to hex for our attack function
    w_hex = w1.hex()
    z1_hex = hex(z1)
    z2_hex = hex(z2)
    
    print(f"    Public w value: {w_hex}")

    # --- STEP 3: EVE ATTACK ---
    print("\n[3] Eve see signatures on blockchain and attack!")
    print("    Eve running math magic...")
    
    recovered_priv_int = recover_key(
        w_hex, 
        alice_pub_hex, 
        msg1, 
        msg2, 
        z1_hex, 
        z2_hex
    )
    
    print(f"    Recovered Key: {hex(recovered_priv_int)}")
    
    if recovered_priv_int == alice_priv:
        print("    [+] KEY MATCH!! EVE HAVE FULL CONTROL NOW!")
    else:
        print("    [-] Fail... something wrong")
        return

    # --- STEP 4: TOTAL THEFT (FORGERY) ---
    print("\n[4] Eve steal everything (Forgery)")
    
    msg_theft = b"Transfer 10000 BTC to EVE (Hacker)"
    print(f"    Forging signature for: {msg_theft}")
    
    # Eve sign use STOLEN key!! she dont need y reuse anymore, she is owner now
    # she verify with Alice Public Key
    (w_forge, z_forge) = sign(msg_theft, recovered_priv_int)
    
    print("    Signature created.")
    
    # --- STEP 5: VERIFY ---
    print("\n[5] Network verify the forged transaction...")
    
    is_valid = verify(msg_theft, alice_pub_bytes, (w_forge, z_forge))
    
    if is_valid:
        print(f"    [+] VALID SIGNATURE! The network accept it.")
        print("    [+] Alice loses 10000 BTC. Game Over.")
    else:
        print("    [-] Invalid? Logic error somewhere.")

    print("\n==================================================")
    print("                 DEMO COMPLETE                    ")
    print("==================================================")

if __name__ == "__main__":
    main()
