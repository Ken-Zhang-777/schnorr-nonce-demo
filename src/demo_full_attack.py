import sys
import os

# setup path again... python path is pain in the ass
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from schnorr_core import sign, verify, N
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
    print("\n[2] Alice sign two transaction with SAME k (oh no...)")
    
    # she use this k for everything... bad bad alice
    FIXED_K = 0x4242424242424242424242424242424242424242424242424242424242424242
    
    msg1 = b"Transfer 1 BTC to Bob"
    msg2 = b"Transfer 5 BTC to Coffee Shop"
    
    print(f"    Signing msg1: {msg1}")
    (R1, s1) = sign(msg1, alice_priv, k_nonce_int=FIXED_K)
    
    print(f"    Signing msg2: {msg2}")
    (R2, s2) = sign(msg2, alice_priv, k_nonce_int=FIXED_K)
    
    # convert to hex for our attack function
    R_hex = R1.hex()
    s1_hex = hex(s1)
    s2_hex = hex(s2)
    
    print(f"    Public R value: {R_hex}")

    # --- STEP 3: EVE ATTACK ---
    print("\n[3] Eve see signatures on blockchain and attack!")
    print("    Eve running math magic...")
    
    recovered_priv_int = recover_key(
        R_hex, 
        alice_pub_hex, 
        msg1, 
        msg2, 
        s1_hex, 
        s2_hex
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
    
    # Eve sign use STOLEN key!! she dont need k reuse anymore, she is owner now
    # she verify with Alice Public Key
    (R_forge, s_forge) = sign(msg_theft, recovered_priv_int)
    
    print("    Signature created.")
    
    # --- STEP 5: VERIFY ---
    print("\n[5] Network verify the forged transaction...")
    
    is_valid = verify(msg_theft, alice_pub_bytes, (R_forge, s_forge))
    
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