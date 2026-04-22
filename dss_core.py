from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class DSSigner:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        self.private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()

    def sign_data(self, data: bytes) -> bytes:
        if not self.private_key:
            raise ValueError("Приватний ключ не знайдено")
        signature = self.private_key.sign(
            data,
            hashes.SHA256()
        )
        return signature

    def verify_data(self, data: bytes, signature: bytes) -> bool:
        if not self.public_key:
            raise ValueError("Публічний ключ не знайдено")
        try:
            self.public_key.verify(
                signature,
                data,
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def save_private_key(self, path: str):
        if not self.private_key:
            raise ValueError("Приватний ключ не згенеровано")
        with open(path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def save_public_key(self, path: str):
        if not self.public_key:
            raise ValueError("Публічний ключ не знайдено")
        with open(path, "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_private_key(self, path: str):
        with open(path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            # Якщо є приватний ключ, можна також отримати публічний
            self.public_key = self.private_key.public_key()

    def load_public_key(self, path: str):
        with open(path, "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
