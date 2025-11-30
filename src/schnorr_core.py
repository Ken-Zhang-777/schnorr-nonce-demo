import hashlib
import os
from coincurve import PrivateKey, PublicKey

# secp256k1 order n... i copy paste this from wiki hope it correct?!
# do not change this or math will break and i will cry
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def hash_to_int(R_bytes, P_bytes, msg_bytes):
    """
    helper to create the challenge e.
    just smash all bytes together and hash it!
    """
    # concat everything... order matter here
    data = R_bytes + P_bytes + msg_bytes
    
    # use sha256 because it classic
    digest = hashlib.sha256(data).digest()
    
    # turn messy bytes into nice big integer
    e_int = int.from_bytes(digest, 'big')
    
    return e_int

def sign(msg_bytes, priv_key_int, k_nonce_int=None):
    """
    create schnorr signature...
    if k_nonce_int provide, we use it (DANGER for demo!!)
    if not, we generate random one.
    """
    
    # 1. get the public key point P from private key x
    # coincurve expect bytes usually so we convert int to 32 bytes
    priv_bytes = priv_key_int.to_bytes(32, 'big')
    P_point = PrivateKey(priv_bytes).public_key
    P_bytes = P_point.format(compressed=True)

    # 2. handle the k (nonce)
    if k_nonce_int is None:
        # safe mode: random k
        # os.urandom is friend for cryptographer
        rand_bytes = os.urandom(32)
        k_int = int.from_bytes(rand_bytes, 'big') % N
    else:
        # DANGER ZONE!!! 
        # we using fixed k... this allows attacker to steal key later
        k_int = k_nonce_int

    # 3. calculate R = k*G
    # cheat: treat k as private key to get corresponding public key (which is k*G)
    k_bytes = k_int.to_bytes(32, 'big')
    R_point = PrivateKey(k_bytes).public_key
    R_bytes = R_point.format(compressed=True)

    # 4. calculate challenge e = hash(R || P || m)
    # math is hard so we delegate to helper
    e_int = hash_to_int(R_bytes, P_bytes, msg_bytes)

    # 5. calculate s = k + e*x mod n
    # this is the magic part... 
    # make sure mod N or number get too big
    s_int = (k_int + (e_int * priv_key_int)) % N

    # return tuple of (R, s)
    # some implementation return just e and s but we do R and s
    return (R_bytes, s_int)

def verify(msg_bytes, pub_key_bytes, signature):
    """
    check if signature valid.
    equation: s*G = R + e*P
    """
    R_bytes, s_int = signature
    
    # check if s is valid range...
    if s_int >= N or s_int <= 0:
        return False # hacker detect?!

    # 1. calculate e same way signer did
    e_int = hash_to_int(R_bytes, pub_key_bytes, msg_bytes)

    # 2. calculate left side: s*G
    # again, treat s as private key to get point
    s_bytes = s_int.to_bytes(32, 'big')
    lhs_point = PrivateKey(s_bytes).public_key

    # 3. calculate right side: R + e*P
    # this part tricky with coincurve api...
    
    # first we need e*P
    try:
        P_point_obj = PublicKey(pub_key_bytes)
        e_bytes = e_int.to_bytes(32, 'big')
        eP_point = P_point_obj.multiply(e_bytes) # scalar mult
    except Exception:
        # maybe bad key?
        return False

    # now we add R + (e*P)
    # coincurve combine_keys function assume adding public keys
    # so we wrap R bytes into PublicKey object first
    try:
        R_point_obj = PublicKey(R_bytes)
        rhs_point = PublicKey.combine_keys([R_point_obj, eP_point])
    except Exception:
        # math fail... probably bad point R
        return False

    # 4. compare left and right
    # need format them to bytes to compare
    if lhs_point.format(compressed=True) == rhs_point.format(compressed=True):
        return True # success!!
    else:
        return False # fake signature :(
    
if __name__ == "__main__":
    # i fix the space here!! python is super picky...
    print("testing schnorr...")
    
    # dummy key
    priv = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    msg = b"give me bitcoin"
    
    # try sign
    sig = sign(msg, priv)
    print("signature generate success:", sig)
    
    # try verify
    # get pubkey first
    pub = PrivateKey(priv.to_bytes(32, 'big')).public_key.format(compressed=True)
    is_valid = verify(msg, pub, sig)
    
    print("is signature valid?? ->", is_valid)