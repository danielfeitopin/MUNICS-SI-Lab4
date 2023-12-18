# DH Ratchet root key
ROOT_KEY: bytes = b'Fully secure key'  # 128 bit (16 bytes) key

# HKDF
HKDF_LENGTH: int = 32  # Size in bytes (twice ROOT_KEY length)
HKDF_INFO: bytes = b'si-lab4-ratchets'  # Application-specific byte sequence

# FLAGS
FLAG_DR_MESSAGE: bytes = b'BEGIN_DR_ENCRYPTED_MESSAGE'
FLAG_SHARE_KEY_FROM: bytes = b'BEGIN_KEY_EXCHANGE_FROM:'
FLAG_SHARE_KEY_KEY: bytes = b'KEY:'

# Nonce
NONCE_LENGTH: int = 96//8  # Nonce length in bytes. NIST recommends 96-bits

# MQTT Connection
MQTT_USER_NAME = # TODO
MQTT_PASSWORD = # TODO
MQTT_IP = # TODO
MQTT_PORT = # TODO
MQTT_KEEPALIVE = # TODO
