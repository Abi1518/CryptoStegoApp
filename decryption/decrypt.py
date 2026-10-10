
from steganography.lsb import decode_image

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES

from security.integrity import generate_hash

import os

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

KEY_FOLDER = os.path.join(
    BASE_DIR,
    "keys"
)

# =========================================================
# RECOVER AES KEY
# =========================================================

def recover_aes_key(
    encrypted_aes_key,
    password,
    key_id
):

    private_key_path = os.path.join(
        KEY_FOLDER,
        f"{key_id}_private.pem"
    )

    if not os.path.isfile(
        private_key_path
    ):

        raise Exception(
            "Required RSA private key was not found."
        )

    # -----------------------------------------------------
    # Load password-protected private key
    # -----------------------------------------------------

    try:

        with open(
            private_key_path,
            "rb"
        ) as key_file:

            private_key = RSA.import_key(
                key_file.read(),
                passphrase=password
            )

    except ValueError:

        raise Exception(
            "Incorrect password."
        )

    # -----------------------------------------------------
    # RSA decrypt
    # -----------------------------------------------------

    cipher_rsa = PKCS1_OAEP.new(
        private_key
    )

    try:

        aes_key = cipher_rsa.decrypt(
            encrypted_aes_key
        )

    except ValueError:

        raise Exception(
            "Unable to recover AES key."
        )

    return aes_key


# =========================================================
# AES DECRYPTION
# =========================================================

def decrypt_data(
    ciphertext,
    aes_key,
    nonce,
    tag
):

    cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    try:

        data = cipher.decrypt_and_verify(
            ciphertext,
            tag
        )

    except ValueError:

        raise Exception(
            "Decryption failed. "
            "The password may be incorrect or "
            "the encrypted data may be corrupted."
        )

    return data


# =========================================================
# RECOVER ORIGINAL FILE
# =========================================================

def recover_file(
    image_path,
    password
):

    # -----------------------------------------------------
    # Decode hidden payload
    # -----------------------------------------------------

    payload = decode_image(
        image_path
    )

    # -----------------------------------------------------
    # Validate payload
    # -----------------------------------------------------

    required_fields = [
        "aes_key",
        "ciphertext",
        "nonce",
        "tag",
        "hash",
        "filename",
        "key_id"
    ]

    for field in required_fields:

        if field not in payload:

            raise Exception(
                f"Invalid encrypted file. "
                f"Missing '{field}'."
            )

    # -----------------------------------------------------
    # Extract payload values
    # -----------------------------------------------------

    encrypted_aes_key = payload[
        "aes_key"
    ]

    ciphertext = payload[
        "ciphertext"
    ]

    nonce = payload[
        "nonce"
    ]

    tag = payload[
        "tag"
    ]

    original_hash = payload[
        "hash"
    ]

    filename = payload[
        "filename"
    ]

    key_id = payload[
        "key_id"
    ]

    # -----------------------------------------------------
    # Recover AES key using RSA
    # -----------------------------------------------------

    aes_key = recover_aes_key(
        encrypted_aes_key,
        password,
        key_id
    )

    # -----------------------------------------------------
    # Decrypt original data
    # -----------------------------------------------------

    original_data = decrypt_data(
        ciphertext,
        aes_key,
        nonce,
        tag
    )

    # -----------------------------------------------------
    # Integrity verification
    # -----------------------------------------------------

    calculated_hash = generate_hash(
        original_data
    )

    print(
        "Stored Hash:",
        original_hash
    )

    print(
        "Calculated Hash:",
        calculated_hash
    )

    if calculated_hash != original_hash:

        raise Exception(
            "Integrity verification failed. "
            "File may have been modified."
        )

    return (
        original_data,
        filename
    )
