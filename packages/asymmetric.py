from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
import os
import base64
import random
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .support import *

# --- #
# RSA #

def generate_keys_rsa():
    """
    Function to generate Public-Private RSA Key-Pair.
    
    :return: Tuple of (public_key, private_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

def public_key_to_bytes_rsa(public_key):
    """
    Function to serialize the public key to bytes (PEM format).
    
    :param public_key: RSA Public Key object.
    :return: Public key in byte format.
    """
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes

def public_key_from_bytes_rsa(public_key_bytes):
    """
    Function to deserialize the public key from bytes.
    
    :param public_key_bytes: Public key in byte format.
    :return: Public key object.
    """
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    return public_key

def encrypt_rsa(public_key, message):
    """
    Function to encrypt plaintext in RSA.

    :param public_key: Public Key from RSA Key-Pair.
    :param message: String Literal.

    :return: String Literal.
    """
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(private_key, ciphertext):
    """
    Function to decrypt ciphertext in RSA.
    
    :param private_key: Private Key from RSA Key-Pair.
    :param ciphertext: String Literal.

    :return: String Literal.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# --- #
# ECC #
# REFER LAB3Q2 #

def generate_keys_ecc():
    """
    Function to generate ECC Public-Private Key-Pair.
    
    :return: Tuple of (public_key, private_key).
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return public_key, private_key

def public_key_to_bytes_ecc(public_key):
    """
    Function to serialize the ECC public key to bytes (PEM format).
    
    :param public_key: ECC Public Key object.
    :return: Public key in byte format.
    """
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes

def public_key_from_bytes_ecc(public_key_bytes):
    """
    Function to deserialize the ECC public key from bytes.
    
    :param public_key_bytes: Public key in byte format.
    :return: ECC public key object.
    """
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    return public_key

def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def derive_symmetric_key(shared_secret, salt):
    # Use Scrypt to derive a key from the shared secret
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(shared_secret)
    return key

def encrypt_ecc(symmetric_key, plaintext):
    """
    Function to encrypt plaintext in ECC.
    """
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad plaintext to be multiple of block size
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + (chr(padding_length) * padding_length)

    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV to the ciphertext

def decrypt_ecc(symmetric_key, ciphertext):
    """
    Function to decrypt ciphertext in ECC.
    """
    iv = ciphertext[:16]  # Extract the IV from the ciphertext
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    padding_length = decrypted_padded_plaintext[-1]  # Last byte tells how much to unpad
    return decrypted_padded_plaintext[:-padding_length].decode('utf-8')  # Remove padding and decode

# -------- #
# El-Gamal #

def generate_keys_elgamal():
    """
    Function to generate El-Gamal Public-Private Key-Pair.
    """
    p = 23  # A small prime number for demonstration purposes
    g = 5   # A generator
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key component
    public_key = (p, g, h)
    private_key = (p, g, h, x)
    return public_key, private_key

def encrypt_elgamal(public_key, message):
    """
    Function to encrypt plaintext in El-Gamal.
    """
    p, g, h = public_key
    # Convert message to an integer by encoding it
    m = int.from_bytes(message.encode('utf-8'), 'big')
    y = random.randint(1, p - 2)  # Random value for encryption
    c1 = pow(g, y, p)  # c1 = g^y mod p
    c2 = (m * pow(h, y, p)) % p  # c2 = m * h^y mod p
    return (c1, c2)

def decrypt_elgamal(private_key, ciphertext, p):
    """
    Function to decrypt ciphertext in El-Gamal.
    """
    x = private_key
    c1, c2 = ciphertext
    # m = c2 * (c1^x)^-1 mod p
    c1_x = pow(c1, x, p)
    c1_x_inv = mod_inverse(c1_x, p)
    m = (c2 * c1_x_inv) % p
    # Convert back to string
    byte_length = (m.bit_length() + 7) // 8  # Calculate the byte length
    return m.to_bytes(byte_length, 'big').decode('utf-8', errors='ignore')

