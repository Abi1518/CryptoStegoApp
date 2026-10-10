from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os


def generate_keys(password, key_folder="keys", key_id=None):
    os.makedirs(key_folder, exist_ok=True)

    key = RSA.generate(2048)

    private_key = key.export_key(
        passphrase=password,
        pkcs=8
    )

    public_key = key.publickey().export_key()

    if key_id:
        private_path = os.path.join(
            key_folder,
            f"{key_id}_private.pem"
        )

        public_path = os.path.join(
            key_folder,
            f"{key_id}_public.pem"
        )
    else:
        private_path = os.path.join(
            key_folder,
            "private.pem"
        )

        public_path = os.path.join(
            key_folder,
            "public.pem"
        )

    with open(private_path, "wb") as file:
        file.write(private_key)

    with open(public_path, "wb") as file:
        file.write(public_key)

    return private_key, public_key


def encrypt_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)

    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    encrypted_key = cipher_rsa.encrypt(aes_key)

    return encrypted_key