from ecdsa import SigningKey, NIST256p, BadSignatureError, VerifyingKey
import hashlib
from .support import *

# ------------------------- #
# Schnorr Digital Signature #

def generate_keys_schnorr():
    """
    Function to generate Schnorr-Signature Public-Private Key-Pair.
    
    :return: Tuple of (public_key, private_key)
    """
    private_key = SigningKey.generate(curve=NIST256p)  # Private key
    public_key = private_key.verifying_key  # Public key
    return public_key, private_key

def public_key_to_bytes_schnorr(public_key):
    """
    Function to serialize the Schnorr private key to bytes.
    
    :param private_key: Schnorr Private Key (SigningKey) object.
    :return: Private key in byte format.
    """
    return public_key.to_string()

def public_key_from_bytes_schnorr(public_key_bytes):
    """
    Function to deserialize the Schnorr public key from bytes.
    
    :param public_key_bytes: Public key in byte format.
    :return: Schnorr Public Key (VerifyingKey) object.
    """
    return VerifyingKey.from_string(public_key_bytes, curve=NIST256p)

def schnorr_sign(message, private_key):
    """
    Generate a Schnorr Signature using Schnorr Private Key.
    """
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign(message_hash, hashfunc=hashlib.sha256)
    return signature

def schnorr_verify(message, signature, public_key):
    """
    Verify a digital signature using Schnorr Public Key.
    """
    try:
        message_hash = hashlib.sha256(message.encode()).digest()
        return public_key.verify(signature, message_hash, hashfunc=hashlib.sha256)
    except BadSignatureError:
        return False

# ---------------------- #
# Diffie-Hellman Key-Gen #

def dh_keygen(bits=256):
    """
    Generate Diffie-Hellman Public Key and Shared Secret.
    """
    p, g = generate_large_prime(bits), random.randint(
        2, (p := generate_large_prime(bits)) - 2
    )
    a, b = random.randint(1, p - 2), random.randint(1, p - 2)
    A, B = pow(g, a, p), pow(g, b, p)
    return (p, g, A, B), (pow(B, a, p), pow(A, b, p))
