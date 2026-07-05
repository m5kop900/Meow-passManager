from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import os

class VaultCrypto:
    @staticmethod
    def derive_key(master_password, salt):
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536,
        )

        return kdf.derive(master_password.encode())

    @staticmethod
    def encrypt(text, key):
        aes = AESGCM(key)

        nonce = os.urandom(12)

        encrypted = aes.encrypt(
            nonce,
            text.encode(),
            None
        )

        return nonce + encrypted

    @staticmethod
    def decrypt(data, key):
        nonce = data[:12]
        ciphertext = data[12:]

        aes = AESGCM(key)

        return aes.decrypt(
            nonce,
            ciphertext,
            None
        ).decode()