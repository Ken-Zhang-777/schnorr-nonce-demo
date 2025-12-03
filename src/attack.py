import sys
import os

# fix path again... python import is drama queen
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from schnorr_core import hash_to_int, q

def recover_key(w_hex, pub_hex, msg1_bytes, msg2_bytes, z1_hex, z2_hex):
    """
    This is the hacker logic!
    Math explanation:
    z1 = y + c1*x
    z2 = y + c2*x
    
    so... z1 - z2 = x*(c1 - c2)
    x = (z1 - z2) / (c1 - c2)
    """
    print(f"[*] Attacking signatures...")
    
    # 1. clean up the inputs (hex -> int/bytes)
    w_bytes = bytes.fromhex(w_hex)
    pub_bytes = bytes.fromhex(pub_hex)
    
    z1 = int(z1_hex, 16)
    z2 = int(z2_hex, 16)
    
    # 2. Re-calculate the challenges (c)
    # we need to know exactly what c was for each signature
    c1 = hash_to_int(w_bytes, pub_bytes, msg1_bytes)
    c2 = hash_to_int(w_bytes, pub_bytes, msg2_bytes)
    
    print(f"    Calculated c1: {hex(c1)[:10]}...")
    print(f"    Calculated c2: {hex(c2)[:10]}...")
    
    # 3. THE MATH TRICK
    # x = (z1 - z2) * inverse(c1 - c2) mod q
    
    # numerator is difference of z
    numerator = (z1 - z2) % q
    
    # denominator is difference of c
    denominator = (c1 - c2) % q
    
    # python 3.8+ allow pow(a, -1, q) for modular inverse!!
    # this is same as 1/denominator in normal math
    try:
        inv_denominator = pow(denominator, -1, q)
    except ValueError:
        print("[X] Math fail! Denominator is zero? Did you sign exact same message twice?")
        return None
        
    # recover x!!
    recovered_priv = (numerator * inv_denominator) % q
    
    return recovered_priv
