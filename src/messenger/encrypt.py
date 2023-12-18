from .config import ROOT_KEY, HKDF_LENGTH, HKDF_INFO
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from os import urandom


def generate_DH_pair() -> tuple[bytes, bytes]:
    """Returns a new Diffie-Hellman key pair based on the Curve25519.

    Returns:
        tuple[bytes, bytes]: Pair (PublicKey, PrivateKey).
    """
    pk: X25519PrivateKey = X25519PrivateKey.generate()
    return (pk.public_key().public_bytes_raw(), pk.private_bytes_raw())


def generate_DH_shared_key(private_key: bytes, public_key: bytes) -> bytes:
    """Returns a new Diffie-Hellman shared key.

    Args:
        private_key (bytes): Bytes for X25519PrivateKey.
        public_key (bytes): Bytes for X25519PublicKey.

    Returns:
        bytes: New shared key.
    """
    return X25519PrivateKey.from_private_bytes(private_key)\
        .exchange(X25519PublicKey.from_public_bytes(public_key))


def derive_root_key(key: bytes, length: int = HKDF_LENGTH,
                    salt: bytes = ROOT_KEY,
                    info: bytes = HKDF_INFO) -> tuple[bytes, bytes]:
    """Derives a key using HKDF.

    Args:
        key (bytes): Key to be derived, output from Diffie-Hellman.
        salt (bytes): A salt.
        info (bytes): Application-specific byte sequence

    Returns:
        tuple[bytes,bytes]: New Root Key and derived key, both of 128 bits.
    """
    derived_key: bytes = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=info
    ).derive(key)
    return (derived_key[:length//2], derived_key[length//2:])


def derive_chain_key(key: bytes) -> tuple[bytes, bytes]:
    """Returns a HMAC instace to be updated by the Symetric Ratchets.

    Args:
        key (bytes): Key to be derived by HMAC.

    Returns:
        tuple[bytes, bytes]: New Chain Key and message key, both of 128 bits.
    """
    derived_key: bytes = HMAC(key, SHA256()).finalize()  # Returns 32 bytes
    return (derived_key[:HKDF_LENGTH//2], derived_key[HKDF_LENGTH//2:])


def get_nonce(length: int) -> bytes:
    """Returns random bytes to be used as a nonce.

    Args:
        length: Number of bytes to output.

    Returns:
        bytes: Random bytes.
    """
    return urandom(length)


def AESGCM_encrypt(key: bytes, nonce: bytes, m: bytes,
                   aad: bytes = None) -> bytes:
    """Encrypts a plaintext using AES-128 in GCM mode.
    Args:
        key (bytes): Key used to encrypt.
        nonce (bytes): Initialization Vector.
        m (bytes): Plaintext to be encrypted.
        aad (bytes): Associated data.
    Returns:
        bytes: The encrypted ciphertext.
    """
    return AESGCM(key).encrypt(nonce=nonce, data=m, associated_data=aad)


def AESGCM_decrypt(key: bytes, nonce: bytes, c: bytes,
                   aad: bytes = None) -> bytes:
    """Decrypts a plaintext using AES-128 in GCM mode.
    Args:
        key (bytes): Key used to encrypt.
        nonce (bytes): Initialization Vector.
        c (bytes): Ciphertext to be decrypted.
        aad (bytes): Associated data.
    Returns:
        bytes: The decrypted ciphertext.
    """
    return AESGCM(key).decrypt(nonce=nonce, data=c, associated_data=aad)
