from typing import Union, Literal
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad


class Cipher:
    """Algorithm to perform encryption/decryption of manager-agent secure messages:
    https://documentation.wazuh.com/current/development/message-format.html#secure-message-format.
    """
    __BLOCK_SIZE = 16
    __AES_IV = b'FEDCBA0987654321'
    __BLOWFISH_IV = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'
    __ALGORITHMS = ['AES', 'BLOWFISH']

    @classmethod
    def encrypt(cls, data: bytes, key: bytes, algorithm: Literal['AES', 'BLOWFISH']) -> bytes:
        cipher, data = cls.__get_cipher_and_data(data, key, algorithm)

        return cipher.encrypt(data)

    @classmethod
    def decrypt(cls, data: bytes, key: bytes, algorithm: Literal['AES', 'BLOWFISH']) -> bytes:
        cipher, data = cls.__get_cipher_and_data(data, key, algorithm)

        return cipher.decrypt(data)

    @classmethod
    def __get_cipher_and_data(cls, data: bytes, key: bytes,
                              algorithm: Literal['AES', 'BLOWFISH']) -> Union[object, bytes]:
        if algorithm not in cls.__ALGORITHMS:
            raise ValueError(f'Invalid encryption/decryption algorithm.')

        if algorithm.upper() == 'AES':
            cipher = AES.new(key[:32], AES.MODE_CBC, cls.__AES_IV)
            data = pad(data, cls.__BLOCK_SIZE)
        elif algorithm.upper() == 'BLOWFISH':
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, cls.__BLOWFISH_IV)

        return cipher, data

    @staticmethod
    def get_encrypted_payload(message: bytes) -> str:
        if (index := message.find(b'#AES:')) is not -1:
            # AES encryption is used
            encrypted_data = message[index + len(b'#AES:'):]
        elif (index := message.find(b':')) is not -1:
            # Blowfish encryption is used
            encrypted_data = message[index + 1:]
        else:
            raise ValueError('Invalid message encryption header.')

        return encrypted_data
