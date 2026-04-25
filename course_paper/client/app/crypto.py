import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: bytes, password: str, *, iterations: int) -> tuple[dict, bytes]:
    salt = os_urandom(SALT_LEN)
    nonce = os_urandom(NONCE_LEN)
    key = _derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    meta = {
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "kdf_iterations": iterations,
    }
    return meta, ciphertext


def decrypt(ciphertext: bytes, password: str, *, salt_b64: str, nonce_b64: str, iterations: int) -> bytes:
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    key = _derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def os_urandom(n: int) -> bytes:
    import os

    return os.urandom(n)

