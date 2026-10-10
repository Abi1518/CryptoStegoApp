
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# =========================================================
# GENERATE AES KEY
# =========================================================

def generate_key():
    """
    Generate a 256-bit AES key.
    """
    return get_random_bytes(32)


# =========================================================
# ENCRYPT DATA
# =========================================================

def encrypt_data(data, key):
    """
    Encrypt data using AES-256-GCM.

    Returns:
        nonce
        ciphertext
        tag
    """

    cipher = AES.new(
        key,
        AES.MODE_GCM
    )

    ciphertext, tag = cipher.encrypt_and_digest(
        data
    )

    return (
        cipher.nonce,
        ciphertext,
        tag
    )
