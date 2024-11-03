from sympy import isprime
import random
import secrets

# ------------------------- #
# GENERAL PURPOSE FUNCTIONS #

def print_red(message):
    print(f"\033[91m{message}\033[0m")

def print_cyan(message):
    print(f"\033[96m{message}\033[00m")

def string_to_bytes(message):
    """
    Convert a String Literal into Bytes Literal.
    """
    return message.encode("utf-8")

def hex_to_bytes(hexstring):
    """
    Convert a Hex String into Bytes Literal.
    """
    return bytes.fromhex(hexstring)

def mod_inverse(a, p):
    """
    Function to return mod inverse of a in domain of p.
    """
    m0, x0, x1 = p, 0, 1
    if p == 1:
        return 0
    while a > 1:
        q = a // p
        m0, p = p, a % p
        a, x0, x1 = m0, x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_large_prime(bits=256):
    return next(n for n in iter(lambda: random.getrandbits(bits), None) if isprime(n))

def generate_large_prime_paillier(bits):
    while True:
        # Generate a random prime number with the desired number of bits
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1  # Ensure p is of the right bit length and odd
        if isprime(p):
            return p
        
def string_to_int(s):
    return int.from_bytes(s.encode('utf-8'), byteorder='big')

def int_to_string(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big').decode("utf-8")

# ----------------------- #
# CLIENT SERVER FUNCTIONS #

def transmit(conn, message):
    """
    Transmit a Packet over Socket Connection.
    :param message: String Literal.
    """
    conn.sendall(message.encode('utf-8'))

def transmit_raw(conn, message):
    """
    Transmit a Packet over Socket Connection.
    :param message: Object.
    """
    conn.sendall(message)

def receive(conn):
    """
    Receive a Packet over Socket Connection.
    
    :return: String Literal.
    """
    return conn.recv(1024).decode()

def receive_raw(conn):
    """
    Receive a Packet over Socket Connection.

    :return: Object.
    """
    return conn.recv(1024)