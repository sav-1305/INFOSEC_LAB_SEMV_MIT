import hashlib

def hash_with_md5(data):
    """
    Compute MD5 hash of the input data.
    param data: String Literal.
    return: String Literal.
    """
    return hashlib.md5(data.encode()).hexdigest()


def hash_with_sha1(data):
    """
    Compute SHA-1 hash of the input data.
    param data: String Literal.
    return: String Literal.
    """
    return hashlib.sha1(data.encode()).hexdigest()


def hash_with_sha256(data):
    """
    Compute SHA-256 hash of the input data.
    param data: String Literal.
    return: String Literal.
    """
    return hashlib.sha256(data.encode()).hexdigest()
