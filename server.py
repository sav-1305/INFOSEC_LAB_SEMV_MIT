#   PYTHON SCRIPT TO IMPLEMENT THE SERVER-END OF A CLIENT-SERVER APPLICATION
#   VIA SOCKET PROGRAMMING.

from packages.support import *
from packages.asymmetric import *
from packages.digitalsign import *
from packages.hashing import *
from packages.key_mgmt import *
from packages.symmetric import *
from packages.phe import *
import socket

# ------- RSA SERVER SIDE ------------------- #
def rsa_serverformalities(conn):
    """
    Generate and Share RSA Key-Pair.

    :param conn: Socket Connection.

    :return: Tuple of Public Key, Private Key.
    """
    # GENERATE AND SHARE ENCRYPTION KEY-PAIR
    print_red("\n#-------ENCRYPTION KEY-------#")

    rsa_public_key, rsa_private_key = generate_keys_rsa()
    rsa_public_key_bytes = public_key_to_bytes_rsa(rsa_public_key)

    transmit_raw(conn, rsa_public_key_bytes)
    print(f"CLIENT MESSAGE: {receive(conn)}")
    
    return rsa_public_key, rsa_private_key

def rsa_serverdecryption(conn, rsa_private_key):
    ciphertext = receive_raw(conn)
    transmit(conn, "CIPHERTEXT RECEIVED")
    print(f"CIPHERTEXT: {ciphertext}")

    plaintext  = decrypt_rsa(rsa_private_key, ciphertext)
    print_cyan(f"\nDECRYPTED TEXT: {plaintext}")

    return plaintext

# ------- ECC SERVER SIDE ------------------- #
def ecc_serverformalities(conn):
    print_red("\n#-------ENCRYPTION KEY-------#")
    ecc_public_key_self, ecc_private_key = generate_keys_ecc()
    ecc_public_key_self_bytes = public_key_to_bytes_ecc(ecc_public_key_self)

    transmit_raw(conn, ecc_public_key_self_bytes)

    ecc_public_key_peer = public_key_from_bytes_ecc(receive_raw(conn))
    print(f"ECC PEER PUBLIC KEY: {ecc_public_key_peer}")

    salt = os.urandom(16)  # Random salt for key derivation
    transmit_raw(conn, salt)


    ecc_shared_key = derive_shared_secret(ecc_private_key, ecc_public_key_peer)
    ecc_symmetric_key = derive_symmetric_key(ecc_shared_key, salt)

    print(f"ECC SHARED SECRET: {ecc_shared_key}")
    print(f"ECC SYMMETRIC KEY: {ecc_symmetric_key}")

    return ecc_symmetric_key, ecc_public_key_self, ecc_private_key

def ecc_serverdecryption(conn, ecc_symmetric_key):
    ciphertext = receive_raw(conn)
    transmit(conn, "CIPHERTEXT RECEIVED.")
    print(f"CIPHERTEXT: {ciphertext}")

    plaintext = decrypt_ecc(ecc_symmetric_key, ciphertext)
    print_cyan(f"\nDECRYPTED TEXT: {plaintext}")

    return plaintext

# ------- PAILLIER SERVER SIDE -------------- #
def phe_serverformalities(conn):
    print_red("\n#-------ENCRYPTION KEY-------#")

    phe_public_key, phe_private_key = generate_paillier_keypair()
    n, g = phe_public_key
    print(f"PHE PUBLIC KEY: ({str(n)[:10]}..., {str(g)[:10]}...)")
    transmit(conn, str(n))
    transmit(conn, str(g))

    print(f"MESSAGE FROM CLIENT: {receive(conn)}")
    
    return phe_public_key, phe_private_key

def phe_serverdecryption(conn, phe_public_key, phe_private_key):
    ciphertext = int(receive(conn))
    print(f"CIPHERTEXT: {ciphertext}")
    
    try:
        plaintext = decrypt_to_string_paillier(phe_private_key, phe_public_key, ciphertext)
        print_cyan(f"\nPLAINTEXT: {plaintext}")
        return plaintext
    except ValueError:
        return "DECRYPTION FAILED"

# ------- SCHNORR SIGNATURE SERVER SIDE ----- #
def schnorr_serverformalities(conn):
    """
    Receive Schnorr Public Key from Client.

    :param conn: Socket Connection.

    :return: Schnorr Public Key. 
    """
    print_red("\n#-------DIGITAL SIGNATURE-------#")

    schnorr_public_key_bytes = receive_raw(conn)
    schnorr_public_key = public_key_from_bytes_schnorr(schnorr_public_key_bytes)

    print(f"SCHNORR PUBLIC KEY: {schnorr_public_key}")
    transmit(conn, "SCHNORR PUBLIC KEY RECEIVED")

    return schnorr_public_key

def schnorr_serververification(conn, plaintext, schnorr_public_key):
    schnorr_signature = receive_raw(conn)

    print(f"DIGITAL SIGNATURE: {schnorr_signature}\n")

    if schnorr_verify(plaintext, schnorr_signature, schnorr_public_key) == True:
        transmit(conn, f"DIG-SIGN VERIFICATION: \033[92mTRUE\033[0m")
        print(f"DIG-SIGN VERIFICATION: \033[92mTRUE\033[0m")
        log_message(f"DIG-SIGN VERIFICATION: TRUE")
    else:
        transmit(conn, "DIG-SIGN VERIFICATION: \033[91mFALSE\033[0m")
        print(f"DIG-SIGN VERIFICATION: \033[91mFALSE\033[0m")
        log_message(f"DIG-SIGN VERIFICATION: FALSE")

# ------- GENERAL PURPOSE FUNCTIONS --------- #
def select_kdc(scheme):
    if scheme == "RSA":
        return KeyDistributionCentre(generate_keys_rsa, "RSA")
    elif scheme == "ECC":
        return KeyDistributionCentre(generate_keys_ecc, "ECC")
    elif scheme == "PHE":
        return KeyDistributionCentre(generate_paillier_keypair, "Paillier")
    else:
        return
    
def log_message(message):
    with open("logfile.txt", "a") as file:
        file.write(message + "\n")

# ------------------------------------------- #
# ------- SERVER CONNECTION ----------------- #
def start_server(host='localhost', port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Server listening on {host}:{port}...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                
                # SETUP
                print_red("\n#-------SETUP-------#")
                scheme = input("ENTER ENCRYPTION SCHEME: ")
                transmit(conn, scheme)

                # KDC
                print_red("\n#-------KEY DISTRIBUTION CENTRE-------#")
                kdc = select_kdc(scheme)
                
                name = input("ENTER YOUR NAME: ")

                # LOG BOOK ENTRY TITLE
                log_message(f"\nNAME: {name}, ENCRYPTION SCHEME: {scheme}")

                # KEY-GEN
                if scheme == "RSA":
                    rsa_public_key, rsa_private_key = rsa_serverformalities(conn)
                elif scheme == "ECC":
                    ecc_symmetric_key, ecc_public_key_self, ecc_private_key = ecc_serverformalities(conn)
                elif scheme == "PHE":
                    phe_public_key, phe_private_key = phe_serverformalities(conn)

                # STORE KEY
                if scheme == "RSA":
                    kdc.store_key(name, rsa_public_key, rsa_private_key)
                elif scheme == "ECC":
                    kdc.store_key(name, ecc_public_key_self, ecc_private_key)
                elif scheme == "PHE":
                    kdc.store_key(name, phe_public_key, phe_private_key)
                

                # RECEIVE DIGITAL SIGNATURE PUBLIC KEY
                schnorr_public_key = schnorr_serverformalities(conn)

                # RECEIVE AND VERIFY ENCRYPTED MESSAGE
                while True:
                    print_red("\n#-------DECRYPTION OF DATA-------#")

                    if scheme == "RSA":
                        plaintext = rsa_serverdecryption(conn, rsa_private_key)
                    elif scheme == "ECC":
                        plaintext = ecc_serverdecryption(conn, ecc_symmetric_key)
                    elif scheme == "PHE":
                        plaintext = phe_serverdecryption(conn, phe_public_key, phe_private_key)
                    log_message(f"DECRYPTED TEXT: {plaintext}")
                
                    print_red("\n#-------SIGNATURE VERIFICATION-------#")
                    schnorr_serververification(conn, plaintext, schnorr_public_key)

if __name__ == "__main__":
    start_server()
