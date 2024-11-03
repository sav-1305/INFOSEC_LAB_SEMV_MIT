#   PYTHON SCRIPT TO IMPLEMENT THE CLIENT-END OF A CLIENT-SERVER APPLICATION
#   VIA SOCKET PROGRAMMING.

from packages.support import *
from packages.asymmetric import *
from packages.digitalsign import *
from packages.hashing import *
from packages.key_mgmt import *
from packages.symmetric import *
from packages.phe import *
import socket

# ------- RSA CLIENT SIDE ------------------- #
def rsa_clientformalities(client_socket):
    """
    Receive RSA Public Key from a Server Socket.
    
    :param client_socket: Socket Connection.

    :return: RSA Public Key.
    """
    # RECEIVE RSA PUBLIC KEY
    print_red("\n#-------ENCRYPTION KEY-------#")
    rsa_public_key_bytes = receive_raw(client_socket)
    rsa_public_key = public_key_from_bytes_rsa(rsa_public_key_bytes)
    print(f"RSA PUBLIC KEY RECEIVED: {rsa_public_key}")
    transmit(client_socket, "RSA PUBLIC KEY RECEIVED")
    return rsa_public_key

def rsa_clientencryption(client_socket, rsa_public_key):
    plaintext  = input("ENTER MESSAGE TO ENCRYPT: ")
    ciphertext = encrypt_rsa(rsa_public_key, plaintext)
    print(f"CIPHERTEXT: {str(ciphertext)[:20]}...")

    transmit_raw(client_socket, ciphertext)
    print(f"\nSERVER MESSAGE: {receive(client_socket)}")

    return plaintext

# ------- ECC CLIENT SIDE ------------------- #
def ecc_clientformalities(client_socket):
    print_red("\n#-------ENCRYPTION KEY-------#")
    ecc_public_key_self, ecc_private_key = generate_keys_ecc()
    ecc_public_key_self_bytes = public_key_to_bytes_ecc(ecc_public_key_self)

    transmit_raw(client_socket, ecc_public_key_self_bytes)
            
    ecc_public_key_peer = public_key_from_bytes_ecc(receive_raw(client_socket))
    print(f"SERVER PUBLIC KEY: {ecc_public_key_peer}")

    salt = receive_raw(client_socket)

    ecc_shared_key = derive_shared_secret(ecc_private_key, ecc_public_key_peer)
    ecc_symmetric_key = derive_symmetric_key(ecc_shared_key, salt)

    print(f"ECC SHARED SECRET: {ecc_shared_key}")
    print(f"ECC SYMMETRIC KEY: {ecc_symmetric_key}")
    
    return ecc_symmetric_key
    
def ecc_clientencryption(client_socket, ecc_symmetric_key):
    plaintext = input("ENTER MESSAGE TO ENCRYPT: ")
    ciphertext = encrypt_ecc(ecc_symmetric_key, plaintext)

    transmit_raw(client_socket, ciphertext)
    print(f"MESSAGE FROM SERVER: {receive(client_socket)}")

    return plaintext

# ------- PAILLIER CLIENT SIDE -------------- #
def phe_clientformalities(client_socket):
    print_red("\n#-------ENCRYPTION KEY-------#")

    n = int(receive(client_socket))
    g = int(receive(client_socket))
    phe_public_key = (n, g)

    print(f"PHE PUBLIC KEY: ({str(n)[:10]}..., {str(g)[:10]}...)")

    transmit(client_socket, "RECEIVED PHE PUBLIC KEY.")

    return phe_public_key

def phe_clientencryption(client_socket, phe_public_key):
    plaintext = input("ENTER MESSAGE TO ENCRYPT: ")
    ciphertext = str(encrypt_string_paillier(phe_public_key, plaintext))
    transmit(client_socket, ciphertext)
    return plaintext

# ------- SCHNORR SIGNATURE CLIENT SIDE ----- #
def schnorr_clientformalities(client_socket):
    """
    Generate Schnorr Key-Pair and send Public Key.

    :param client_socket: Socket Connection.

    :return: Tuple of Schnorr Public key, Private Key
    """
    # GENERATE SCHNORR KEY
    print_red("\n#-------DIGITAL SIGNATURE-------#")

    schnorr_public_key, schnorr_private_key = generate_keys_schnorr()
    schnorr_public_key_bytes = public_key_to_bytes_schnorr(schnorr_public_key)

    transmit_raw(client_socket, schnorr_public_key_bytes)
    print(f"SERVER MESSAGE: {receive(client_socket)}")

    return schnorr_public_key, schnorr_private_key

def schnorr_clientsign(client_socket, plaintext, schnorr_private_key):
    schnorr_signature = schnorr_sign(plaintext, schnorr_private_key)
    transmit_raw(client_socket, schnorr_signature)
    print(f"SERVER MESSAGE: {receive(client_socket)}")


# ------------------------------------------- #
# ------- CLIENT CONNECTION ----------------- #
def start_client(host='localhost', port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # CONNECT TO CLIENT
        client_socket.connect((host, port))

        # IDENTIFY SCHEME
        print_red("\n#-------SETUP-------#")
        scheme = receive(client_socket)
        print(f"ENCRYPTION SCHEME: {scheme}")

        # RECEIVE PUBLIC KEY
        if scheme == "RSA":
            rsa_public_key = rsa_clientformalities(client_socket)
        elif scheme == "ECC":
            ecc_symmetric_key = ecc_clientformalities(client_socket)
        elif scheme == "PHE":
            phe_public_key = phe_clientformalities(client_socket)

        # GENERATE AND SHARE SCHNORR KEY-PAIR
        schnorr_public_key, schnorr_private_key = schnorr_clientformalities(client_socket)

        while True:
            # ENCRYPT MESSAGE
            print_red("\n#-------ENCRYPTION OF DATA-------#")

            if scheme == "RSA":
                plaintext = rsa_clientencryption(client_socket, rsa_public_key)
            elif scheme == "ECC":
                plaintext = ecc_clientencryption(client_socket, ecc_symmetric_key)
            elif scheme == "PHE":
                plaintext = phe_clientencryption(client_socket, phe_public_key)

            # VERIFY SIGNATURE
            print_red("\n#-------SIGNATURE VERIFICATION-------#")
            schnorr_clientsign(client_socket, plaintext, schnorr_private_key)


            


if __name__ == "__main__":
    start_client()
