import sys
import os

# fix path again... python import is drama queen
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from schnorr_core import hash_to_int, N

def recover_key(R_hex, pub_hex, msg1_bytes, msg2_bytes, s1_hex, s2_hex):
    """
    This is the hacker logic!
    s1 = k + e1*x
    s2 = k + e2*x
    
    so... s1 - s2 = x*(e1 - e2)
    x = (s1 - s2) / (e1 - e2)
    """
    print(f"[*] Attacking signatures...")
    
    # 1. clean up the inputs (hex -> int/bytes)
    R_bytes = bytes.fromhex(R_hex)
    pub_bytes = bytes.fromhex(pub_hex)
    
    s1 = int(s1_hex, 16)
    s2 = int(s2_hex, 16)
    
    # 2. Re-calculate the challenges (e)
    # we need to know exactly what e was for each signature
    e1 = hash_to_int(R_bytes, pub_bytes, msg1_bytes)
    e2 = hash_to_int(R_bytes, pub_bytes, msg2_bytes)
    
    print(f"    Calculated e1: {hex(e1)[:10]}...")
    print(f"    Calculated e2: {hex(e2)[:10]}...")
    
    # 3. THE MATH TRICK
    # x = (s1 - s2) * inverse(e1 - e2) mod N
    
    # numerator is difference of s
    numerator = (s1 - s2) % N
    
    # denominator is difference of e
    denominator = (e1 - e2) % N
    
    # python 3.8+ allow pow(a, -1, N) for modular inverse!!
    # this is same as 1/denominator in normal math
    try:
        inv_denominator = pow(denominator, -1, N)
    except ValueError:
        print("[X] Math fail! Denominator is zero? Did you sign exact same message twice?")
        return None
        
    # recover x!!
    recovered_priv = (numerator * inv_denominator) % N
    
    return recovered_priv

if __name__ == "__main__":
    # --- DATA STOLEN FROM YOUR TERMINAL ---
    # i copy paste specific values from your previous run
    
    victim_R = "02b9cb4e655f1c6cc4f61209130f967ee4fe27aef2d8a5506f350c7c5b8dcdd4d2"
    victim_Pub = "036364d480b89ce1feff1a81e48dced8b90711980175037b202d5cb7b4dc591fa0"
    
    m1 = b"I love crypto"
    s1_hex = "0x6320abd91f67e20ec6c993d7f8317aae5d957c603ca1c46239513174bb440c8e"
    
    m2 = b"I reuse nonces"
    s2_hex = "0xfad6f9727d8d75d53718b2433bd9096abdfab4f6616d0e961a7945193a62e46e"

    # RUN ATTACK
    priv_int = recover_key(victim_R, victim_Pub, m1, m2, s1_hex, s2_hex)
    
    print("-" * 30)
    print("CALCULATED PRIVATE KEY:")
    print(hex(priv_int))
    print("-" * 30)
    
    # Check if matches the secret one from day 3 output
    # Secret was: f052c7899fae8965d1b3dc3bdfe6ea067c17582f027e8923e093112f07afc2c0
    target = 0xf052c7899fae8965d1b3dc3bdfe6ea067c17582f027e8923e093112f07afc2c0
    
    if priv_int == target:
        print("✅ SUCCESS!! WE STOLE THE KEY!! HACKERMAN!!")
    else:
        print("❌ FAIL... math is broken or values wrong copy paste")
