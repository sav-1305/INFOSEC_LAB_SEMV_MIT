from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# ---------- #
# SIMPLE-DES #

def encrypt_DES(msg, key) :
    """
    Encrypt a plaintext in DES.
    param msg: string literal
    param key: byte literal
    """
    cipher = DES.new(key, DES.MODE_EAX)
    nonce  = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def decrypt_DES(nonce, ciphertext, tag, key) :
    """
    Decrypt a ciphertext in DES.
    """
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try :
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

# ------- #
# AES #

def encrypt_AES(plaintext, key, iv) :
    """
    Encrypt a plaintext in AES.
    param plaintext: String Literal.
    param key: Byte Literal.
    param iv: Byte Literal.
    """
    cipher  = AES.new(key, AES.MODE_CBC, iv)
    message = plaintext.encode()
    message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def decrypt_AES(ciphertext, key, iv) :
    cipher  = AES.new(key, AES.MODE_CBC, iv)
    message = cipher.decrypt(ciphertext)
    message = unpad(message, AES.block_size)
    plaintext = message.decode()
    return plaintext

# ---- #
# DES3 #

def Create_3DES_key(key) :
    key_bytes = binascii.unhexlify(key)
    try:
        key = DES3.adjust_key_parity(key_bytes)
    except ValueError as e:
        raise ValueError("Invalid 3DES key, degenerates to single DES. Provide a stronger key.") from e
    return key_bytes

def Encrypt_3DES(plaintext, key) :
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_text = pad(plaintext.encode(), DES3.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext

def Decrypt_3DES(ciphertext, key) :
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_padded_text = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded_text, DES3.block_size).decode()
    return plaintext