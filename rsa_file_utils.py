import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 128
ENCRYPTED_CHUNK_SIZE = 256

def generate_rsa_keys(private_key_path: str, public_key_path: str):
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()

    # приватний ключ
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ))

    # публічний ключ
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def _get_padding():
    return padding.OAEP(
        mgf = padding.MGF1(algorithm = hashes.SHA256()),
        algorithm = hashes.SHA256(),
        label = None
    )


def encrypt_file_rsa(input_path: str, output_path: str, public_key_path: str):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend = default_backend()
        )

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = public_key.encrypt(chunk, _get_padding())
            f_out.write(encrypted_chunk)


def decrypt_file_rsa(input_path: str, output_path: str, private_key_path: str):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend()
        )

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        while True:
            chunk = f_in.read(ENCRYPTED_CHUNK_SIZE)
            if not chunk:
                break
            decrypted_chunk = private_key.decrypt(chunk, _get_padding())
            f_out.write(decrypted_chunk)
