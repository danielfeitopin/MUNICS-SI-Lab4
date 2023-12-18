from .config import FLAG_DR_MESSAGE, NONCE_LENGTH
from .encrypt import (generate_DH_shared_key, generate_DH_pair, derive_root_key,
                      derive_chain_key, AESGCM_encrypt, AESGCM_decrypt,
                      get_nonce)


class SymetricKeyRatchet:
    def __init__(self, chain_key: bytes) -> None:
        self.chain_key: bytes = chain_key
        self.chain_n: int = 0  # Message numbers for sending

    def step(self) -> tuple[bytes, bytes]:
        kdf_out: tuple[bytes, bytes] = derive_chain_key(self.chain_key)
        self.chain_key: bytes = kdf_out[0]
        return (kdf_out[0], kdf_out[1])


class DHRatchet:
    def __init__(self, dh_keys: tuple[bytes, bytes], peer_key: bytes,
                 root_key: bytes) -> None:

        # Diffie-Hellman keys
        self.public_key: bytes = dh_keys[0]
        self.private_key: bytes = dh_keys[1]
        self.peer_key: bytes = peer_key

        self.root_key: bytes = root_key

    def step(self) -> tuple[bytes, bytes]:

        # First root KDF chain update
        kdf_out1: tuple[bytes, bytes] = derive_root_key(
            key=generate_DH_shared_key(self.private_key, self.peer_key),
            salt=self.root_key
        )
        self.root_key: bytes = kdf_out1[0]

        # Second root KDF chain update
        kdf_out2: tuple[bytes, bytes] = derive_root_key(
            key=generate_DH_shared_key(self.private_key, self.peer_key),
            salt=self.root_key
        )
        self.root_key: bytes = kdf_out2[0]

        return (kdf_out1[1], kdf_out2[1])

    def update_peer_key(self, peer_key: bytes) -> None:
        self.peer_key: bytes = peer_key
        self.step()
        return

    def update_dh_keys(self, dh_keys: tuple[bytes, bytes] = None) -> None:
        if dh_keys is None:
            dh_keys: tuple[bytes, bytes] = generate_DH_pair()
        self.public_key: bytes = dh_keys[0]
        self.private_key: bytes = dh_keys[1]
        self.step()
        return


class DoubleRatchet(DHRatchet):
    def __init__(self, dh_keys: tuple[bytes, bytes], peer_key: bytes,
                 root_key: bytes, active: bool = True) -> None:
        super().__init__(dh_keys, peer_key, root_key)

        self.__active: bool = active
        self.recv_ratchet: SymetricKeyRatchet = None
        self.send_ratchet: SymetricKeyRatchet = None
        self.step()

    def step(self) -> tuple[bytes, bytes]:

        # First root KDF chain update
        kdf_out1: tuple[bytes, bytes] = derive_root_key(
            key=generate_DH_shared_key(self.private_key, self.peer_key),
            salt=self.root_key
        )
        self.root_key: bytes = kdf_out1[0]

        # Second root KDF chain update
        kdf_out2: tuple[bytes, bytes] = derive_root_key(
            key=generate_DH_shared_key(self.private_key, self.peer_key),
            salt=self.root_key
        )
        self.root_key: bytes = kdf_out2[0]

        # Reset symetric ratchets
        if self.__active:
            self.recv_ratchet = SymetricKeyRatchet(kdf_out1[1])
            self.send_ratchet = SymetricKeyRatchet(kdf_out2[1])
        else:
            self.send_ratchet = SymetricKeyRatchet(kdf_out1[1])
            self.recv_ratchet = SymetricKeyRatchet(kdf_out2[1])

        return (kdf_out1[1], kdf_out2[1])

    def encrypt(self, m: bytes) -> bytes:
        message_key: bytes = self.send_ratchet.step()[1]
        nonce: bytes = get_nonce(NONCE_LENGTH)
        c: bytes = AESGCM_encrypt(message_key, nonce, m)
        self.update_dh_keys()  # UPDATE
        payload: bytes = FLAG_DR_MESSAGE + self.public_key + nonce + c
        return payload

    def decrypt(self, payload: bytes) -> bytes | None:

        # Check and remove flag
        if not payload.startswith(FLAG_DR_MESSAGE):
            return None
        else:
            payload: bytes = payload[len(FLAG_DR_MESSAGE):]

        # Process peer public key
        peer_public_key: bytes = payload[:len(self.peer_key)]
        payload: bytes = payload[len(self.peer_key):]

        # Retrieve nonce
        nonce: bytes = payload[:NONCE_LENGTH]
        payload: bytes = payload[NONCE_LENGTH:]

        # Decrypt ciphertext
        message_key: bytes = self.recv_ratchet.step()[1]
        m: bytes = AESGCM_decrypt(message_key, nonce, payload)

        # Update peer public key if necessary
        if not peer_public_key == self.peer_key:
            self.update_peer_key(peer_public_key)

        return m
