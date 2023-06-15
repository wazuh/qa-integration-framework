from typing import Union, Literal, Tuple
import zlib
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad


class SecureMessage:
    """Class to handle the manager-agent secure messages:
    https://documentation.wazuh.com/current/development/message-format.html#secure-message-format.
    """
    __block_size = 16
    __aes_iv = b'FEDCBA0987654321'
    __blowfish_iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'

    algorithm_headers = {'AES': b'#AES:', 'BLOWFISH': b':'}

    @classmethod
    def encrypt(cls, data: bytes, key: bytes, algorithm: Literal['AES', 'BLOWFISH']) -> bytes:
        cipher, data = cls.__get_cipher_and_data(data, key, algorithm)

        return cipher.encrypt(data)

    @classmethod
    def decrypt(cls, data: bytes, key: bytes, algorithm: Literal['AES', 'BLOWFISH']) -> bytes:
        cipher, data = cls.__get_cipher_and_data(data, key, algorithm)

        return cipher.decrypt(data)

    @classmethod
    def extract_payload_and_algorithm(cls, message: bytes) -> Tuple[bytes, Literal['AES', 'BLOWFISH']]:
        """
        Extracts the payload and encryption algorithm from a given wazuh message.

        Args:
            message (bytes): The message from which to extract the payload and encryption algorithm.

        Returns:
            Tuple[bytes, Literal['AES', 'BLOWFISH']]: The extracted payload and encryption algorithm.

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

    @staticmethod
    def decompress_and_decode(message):
        padding = next((index for index, char in enumerate(
                        message) if char != 33), len(message))

        msg_remove_padding = message[padding:]
        msg_decompress = zlib.decompress(msg_remove_padding)
        msg_decoded = msg_decompress.decode('ISO-8859-1')

        return msg_decoded

    # Internal Methods

    @classmethod
    def __get_cipher_and_data(cls, data: bytes, key: bytes,
                              algorithm: Literal['AES', 'BLOWFISH']) -> Union[object, bytes]:
        if algorithm not in cls.algorithm_headers.keys():
            raise ValueError(f'Invalid encryption/decryption algorithm.')

        if algorithm.upper() == 'AES':
            cipher = AES.new(key[:32], AES.MODE_CBC, cls.__aes_iv)
            data = pad(data, cls.__block_size)
        elif algorithm.upper() == 'BLOWFISH':
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, cls.__blowfish_iv)

        return cipher, data
