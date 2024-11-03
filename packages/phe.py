from sympy import isprime
from .support import *

# ------- Paillier Homomorphic Scheme ------- #

# Generate Paillier Key Pair
def generate_paillier_keypair(bits=512):
    """
    Generate a Paillier Key-Pair.

    :return: Tuple of public_key, private_key.
    """
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    n = p * q
    g = n + 1
    lambda_n = (p - 1) * (q - 1)
    mu = mod_inverse(lambda_n, n)
    public_key = (n, g)
    private_key = (lambda_n, mu)
    return public_key, private_key

def encrypt_paillier(public_key, message):
    n, g = public_key
    r = secrets.randbelow(n - 1) + 1
    n_squared = n ** 2
    ciphertext = (pow(g, message, n_squared) * pow(r, n, n_squared)) % n_squared
    return ciphertext

def decrypt_paillier(private_key, public_key, ciphertext):
    lambda_n, mu = private_key
    n, _ = public_key
    n_squared = n ** 2
    x = (pow(ciphertext, lambda_n, n_squared) - 1) // n
    message = (x * mu) % n
    return message

# Encrypt a string
def encrypt_string_paillier(public_key, message):
    message_int = string_to_int(message)
    return encrypt_paillier(public_key, message_int)

# Decrypt to string
def decrypt_to_string_paillier(private_key, public_key, ciphertext):
    message_int = decrypt_paillier(private_key, public_key, ciphertext)
    return int_to_string(message_int)
    # return message_int