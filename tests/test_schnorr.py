import pytest
import os
import sys

# HACK: force python to look at parent directory (project root)
# otherwise it cant find 'src' and crash!
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from coincurve import PrivateKey
# import our messy code from day 1
from src.schnorr_core import sign, verify, N

def test_schnorr_happy_path():
    """
    test if normal signature work perfect.
    we expect verify return True here.
    """
    # 1. setup key
    # random bytes for privkey
    priv_bytes = os.urandom(32)
    priv_int = int.from_bytes(priv_bytes, 'big')
    
    # get pubkey bytes
    pub_bytes = PrivateKey(priv_bytes).public_key.format(compressed=True)
    
    # 2. sign something
    msg = b"hello this is valid message"
    signature = sign(msg, priv_int)
    
    # 3. verify!
    result = verify(msg, pub_bytes, signature)
    
    # assert mean "if this not True, crash and burn"
    assert result == True

def test_verify_fail_wrong_message():
    """
    if hacker change message in transit... 
    verify function MUST say False!
    """
    # setup
    priv_bytes = os.urandom(32)
    priv_int = int.from_bytes(priv_bytes, 'big')
    pub_bytes = PrivateKey(priv_bytes).public_key.format(compressed=True)
    
    # sign original message
    msg = b"pay alice 10 btc"
    signature = sign(msg, priv_int)
    
    # attacker change message!
    fake_msg = b"pay EVE 10 btc"
    
    # verify should fail
    result = verify(fake_msg, pub_bytes, signature)
    
    # verify result must be False
    assert result == False

def test_verify_fail_tamper_signature():
    """
    if hacker change the signature value (s)...
    it should be invalid math.
    """
    priv_bytes = os.urandom(32)
    priv_int = int.from_bytes(priv_bytes, 'big')
    pub_bytes = PrivateKey(priv_bytes).public_key.format(compressed=True)
    
    msg = b"dont touch my signature"
    (R_bytes, s_int) = sign(msg, priv_int)
    
    # TAMPER!! change s value by adding 1
    fake_s = (s_int + 1) % N
    bad_signature = (R_bytes, fake_s)
    
    # check...
    result = verify(msg, pub_bytes, bad_signature)
    assert result == False

def test_verify_fail_wrong_pubkey():
    """
    checking signature with wrong person public key?
    should fail obviously.
    """
    # person A key
    priv_a = int.from_bytes(os.urandom(32), 'big')
    
    # person B key
    priv_b_bytes = os.urandom(32)
    pub_b_bytes = PrivateKey(priv_b_bytes).public_key.format(compressed=True)
    
    msg = b"identity theft is joke?"
    
    # A sign it
    sig_from_a = sign(msg, priv_a)
    
    # verify with B public key
    result = verify(msg, pub_b_bytes, sig_from_a)
    assert result == False