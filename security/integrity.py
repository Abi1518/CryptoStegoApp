import hashlib


def generate_hash(data):

    sha256 = hashlib.sha256()

    sha256.update(data)

    return sha256.hexdigest()