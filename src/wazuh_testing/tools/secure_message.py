import hashlib
import zlib

from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad
from typing import Union, Literal, Tuple


class SecureMessage:
    """Class to handle the manager-agent secure messages:
    https://documentation.wazuh.com/current/development/message-format.html#secure-message-format.
    """
    __block_size = 16
    __aes_iv = b'FEDCBA0987654321'
    __blowfish_iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'

    algorithm_headers = {'AES': b'#AES:', 'BLOWFISH': b':'}

    @classmethod
    def encrypt(cls, message: bytes, key: bytes, algorithm: str) -> bytes:
        cipher, data = cls.__get_cipher_and_data(message, key, algorithm)

        return cls.__set_algorithm_header(cipher.encrypt(data), algorithm)

    @classmethod
    def decrypt(cls, message: bytes, key: bytes) -> bytes:
        payload, algorithm = cls.__get_payload_and_algorithm(message)
        cipher, data = cls.__get_cipher_and_data(payload, key, algorithm)

        return cipher.decrypt(data)

    @staticmethod
    def decode(message: bytes) -> str:
        padding = next((index for index, char in enumerate(
                        message) if char != 33), len(message))

        msg_remove_padding = message[padding:]
        msg_decompress = zlib.decompress(msg_remove_padding)

        return msg_decompress.decode('ISO-8859-1')

    @classmethod
    def encode(cls, message: bytes) -> str:
        # Compose sec message
        payload = b'55555' + b'1234567891' + b':' + b'0227' + b':' + message
        message_hash = hashlib.md5(payload).hexdigest()
        payload = message_hash.encode() + payload
        # Compress
        compressed_payload = zlib.compress(payload)
        # Padding
        padding = (b'!' * (8 - extra if (extra := len(compressed_payload) % 8) > 0 else 8))
        padded_payload = padding + compressed_payload

        return padded_payload

    @staticmethod
    def extract_agent_id(message: bytes) -> Union[str, None]:
        """
        Extracts the agent ID from a given Wazuh message.

        In Wazuh, the agent ID is sent within the message, enclosed between 
        two exclamation marks '!'. Example: !001!: RestOfTheMsg...

        Args:
            message (bytes): The message from which to extract the agent ID.

        Returns:
            Union[str, None]: The ID as a string if it comes on the message. Otherwise None.
        """
        if not b'!' in message:
            return None

        # Get the agent ID from the message. Example: !001!
        start_index = message.find(b'!') + 1
        end_index = message.find(b'!', start_index)

        return message[start_index: end_index].decode()

    # Internal Methods

    @classmethod
    def __get_payload_and_algorithm(cls, message: bytes) -> Tuple[bytes, str]:
        """
        Extracts the payload and encryption algorithm from a given wazuh message.

        Args:
            message (bytes): The message from which to extract the payload and encryption algorithm.

        Returns:
            Tuple[bytes, str]: The extracted payload and encryption algorithm.

        Raises:
            ValueError: If the message encryption header is invalid.
        """
        if (index := message.find(cls.algorithm_headers['AES'])) is not -1:
            # AES encryption is used
            algorithm = 'AES'
            payload = message[index + 5:]
        elif (index := message.find(cls.algorithm_headers['BLOWFISH'])) is not -1:
            # Blowfish encryption is used
            algorithm = 'BLOWFISH'
            payload = message[index + 1:]
        else:
            raise ValueError('Invalid message encryption header.')

        return payload, algorithm

    @classmethod
    def __set_algorithm_header(cls, message: bytes, algorithm: str) -> bytes:
        """
        Extracts the payload and encryption algorithm from a given wazuh message.

        Args:
            message (bytes): The message from which to extract the payload and encryption algorithm.

        Returns:
            Tuple[bytes, str]: The extracted payload and encryption algorithm.

        Raises:
            ValueError: If the message encryption header is invalid.
        """
        if algorithm not in cls.algorithm_headers.keys():
            raise ValueError('Invalid message encryption algorithm.')
        header = cls.algorithm_headers[algorithm.upper()]
        return header + message

    @classmethod
    def __get_cipher_and_data(cls, payload: bytes, key: bytes,
                              algorithm: Literal['AES', 'BLOWFISH']) -> Union[object, bytes]:
        if algorithm.upper() not in cls.algorithm_headers.keys():
            raise ValueError(f'Invalid encryption/decryption algorithm.')

        if algorithm.upper() == 'AES':
            cipher = AES.new(key[:32], AES.MODE_CBC, cls.__aes_iv)
            payload = pad(payload, cls.__block_size)
        elif algorithm.upper() == 'BLOWFISH':
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, cls.__blowfish_iv)

        return cipher, payload
