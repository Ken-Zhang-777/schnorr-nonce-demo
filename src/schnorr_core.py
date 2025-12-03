import hashlib
import os
from coincurve import PrivateKey, PublicKey

# secp256k1 order q... i copy paste this from wiki hope it correct?!
# do not change this or math will break and i will cry
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def hash_to_int(w_bytes, P_bytes, msg_bytes):
    """
    helper to create the challenge c.
    just smash all bytes together and hash it!
    """
    # concat everything... order matter here
    data = w_bytes + P_bytes + msg_bytes
    
    # use sha256 because it classic
    digest = hashlib.sha256(data).digest()
    
    # turn messy bytes into nice big integer
    c_int = int.from_bytes(digest, 'big')
    
    return c_int

def sign(msg_bytes, priv_key_int, y_nonce_int=None):
    """
    create schnorr signature...
    if y_nonce_int provide, we use it (DANGER for demo!!)
    if not, we generate random one.
    """
    
    # 1. get the public key point P from private key x
    # coincurve expect bytes usually so we convert int to 32 bytes
    priv_bytes = priv_key_int.to_bytes(32, 'big')
    P_point = PrivateKey(priv_bytes).public_key
    P_bytes = P_point.format(compressed=True)

    # 2. handle the y (nonce)
    if y_nonce_int is None:
        # safe mode: random y
        # os.urandom is friend for cryptographer
        rand_bytes = os.urandom(32)
        y_int = int.from_bytes(rand_bytes, 'big') % q
    else:
        # DANGER ZONE!!! 
        # we using fixed y... this allows attacker to steal key later
        y_int = y_nonce_int

    # 3. calculate w = y*G
    # cheat: treat y as private key to get corresponding public key (which is y*G)
    y_bytes = y_int.to_bytes(32, 'big')
    w_point = PrivateKey(y_bytes).public_key
    w_bytes = w_point.format(compressed=True)

    # 4. calculate challenge c = hash(w || P || m)
    # math is hard so we delegate to helper
    c_int = hash_to_int(w_bytes, P_bytes, msg_bytes)

    # 5. calculate z = y + c*x mod q
    # this is the magic part... 
    # make sure mod q or number get too big
    z_int = (y_int + (c_int * priv_key_int)) % q

    # return tuple of (w, z)
    # some implementation return just c and z but we do w and z
    return (w_bytes, z_int)

def verify(msg_bytes, pub_key_bytes, signature):
    """
    check if signature valid.
    equation: z*G = w + c*P
    """
    w_bytes, z_int = signature
    
    # check if z is valid range...
    if z_int >= q or z_int <= 0:
        return False # hacker detect?!

    # 1. calculate c same way signer did
    c_int = hash_to_int(w_bytes, pub_key_bytes, msg_bytes)

    # 2. calculate left side: z*G
    # again, treat z as private key to get point
    z_bytes = z_int.to_bytes(32, 'big')
    lhs_point = PrivateKey(z_bytes).public_key

    # 3. calculate right side: w + c*P
    # this part tricky with coincurve api...
    
    # first we need c*P
    try:
        P_point_obj = PublicKey(pub_key_bytes)
        c_bytes = c_int.to_bytes(32, 'big')
        cP_point = P_point_obj.multiply(c_bytes) # scalar mult
    except Exception:
        # maybe bad key?
        return False

    # now we add w + (c*P)
    # coincurve combine_keys function assume adding public keys
    # so we wrap w bytes into PublicKey object first
    try:
        w_point_obj = PublicKey(w_bytes)
        rhs_point = PublicKey.combine_keys([w_point_obj, cP_point])
    except Exception:
        # math fail... probably bad point w
        return False

    # 4. compare left and right
    # need format them to bytes to compare
    if lhs_point.format(compressed=True) == rhs_point.format(compressed=True):
        return True # success!!
    else:
        return False # fake signature :(
