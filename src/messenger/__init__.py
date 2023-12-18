from .config import (FLAG_SHARE_KEY_FROM, FLAG_SHARE_KEY_KEY, FLAG_DR_MESSAGE,
                     ROOT_KEY)
from .encrypt import generate_DH_pair
from .mqtt import MQTT
from .rachets import DoubleRatchet
from enum import Enum


class ClientState(Enum):
    PASSIVE = 0
    ACTIVE = 1
    CONNECTED = 2


class Client:

    def __init__(self, user_name: str, state: ClientState) -> None:

        self.user_name: str = user_name
        self.user_keys: tuple[bytes, bytes] = generate_DH_pair()

        self.peer_name: str = None

        self.state: ClientState = state

        self.mqtt_client: MQTT = MQTT()
        self.mqtt_client.connect()
        self.mqtt_client.subscribe(self.user_name)

        self.ratchet: DoubleRatchet = None

    def send_public_key(self, peer_name: str) -> None:
        """Starts connection with other client.

        Args:
            peer_name (str): Client name.
        """
        self.peer_name = peer_name
        payload: bytes = b''
        payload += FLAG_SHARE_KEY_FROM
        payload += self.user_name.encode()
        payload += FLAG_SHARE_KEY_KEY
        payload += self.user_keys[0]
        self.mqtt_client.publish(topic=self.peer_name, payload=payload)
        return

    def send_message(self, m: str) -> None:
        """Sends meesage to peer.

        Args:
            m (str): Mesage to encrypt and send.
        """
        if self.state == ClientState.CONNECTED:
            c: bytes = self.ratchet.encrypt(m.encode())
            self.mqtt_client.publish(topic=self.peer_name, payload=c)
        return

    def process_messages(self, payload: bytes) -> None:
        """Processes the incoming messages according to their header flags.

        Args:
            payload (bytes): Received message content.
        """

        def retrieve_name_and_key(payload: bytes) -> tuple[bytes, bytes] | None:

            # Check flags
            name_flag_index = payload.find(FLAG_SHARE_KEY_FROM)
            if name_flag_index != 0:
                return None

            key_flag_index = payload.find(FLAG_SHARE_KEY_KEY)
            if key_flag_index == -1:
                return None

            name_begin_index = name_flag_index+len(FLAG_SHARE_KEY_FROM)
            name: bytes = payload[name_begin_index:key_flag_index]

            public_key_begin_index = key_flag_index+len(FLAG_SHARE_KEY_KEY)
            public_key: bytes = payload[public_key_begin_index:]

            return (name, public_key)

        # Begining of connection
        if payload.startswith(FLAG_SHARE_KEY_FROM):
            name, public_key = retrieve_name_and_key(payload)
            name: str = name.decode()

            if self.state == ClientState.PASSIVE:
                self.peer_name: str = name
                print(f"[INFO] Received public key from {self.peer_name}.")
                print(f"[INFO] Sending public key to {self.peer_name}.")
                self.send_public_key(self.peer_name)
                self.state = ClientState.CONNECTED
                self.ratchet = DoubleRatchet(self.user_keys, public_key,
                                             ROOT_KEY, False)
                print('[INFO] Connection stablished.')

            if self.state == ClientState.ACTIVE and self.peer_name == name:
                self.state = ClientState.CONNECTED
                self.ratchet = DoubleRatchet(self.user_keys, public_key,
                                             ROOT_KEY)
                print('[INFO] Connection stablished.')

        # Encrypted message received
        if payload.startswith(FLAG_DR_MESSAGE) \
                and self.state == ClientState.CONNECTED:

            # Decrypt
            try:
                message: bytes | None = self.ratchet.decrypt(payload)
                if message is not None:
                    print(f'{self.peer_name}: {message.decode()}')
            except:
                print('[ERROR] Error decrypting.')

        return

    def wait_for_public_key(self) -> None:
        """Wait until public key message is received"""
        def on_message(client, userdata, message):
            self.process_messages(message.payload)
            self.mqtt_client.disconnect()
        self.mqtt_client.on_message = on_message
        print(f'[INFO] Waiting for public key...')
        self.mqtt_client.loop_forever()
        return

    def wait_for_messages(self) -> None:
        """Keep listening for encrypted messages"""
        def on_message(client, userdata, message):
            self.process_messages(message.payload)
        self.mqtt_client.on_message = on_message
        self.mqtt_client.connect()
        self.mqtt_client.subscribe(self.user_name)
        self.mqtt_client.loop_start()
        return
