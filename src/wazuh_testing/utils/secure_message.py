# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import hashlib
import struct
import zlib

from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad
from typing import Union, Tuple


# Internal constants.
__BLOCK_SIZE = 16
__AES_IV = b'FEDCBA0987654321'
__BLOWFISH_IC = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'

ALGORITHM_HEADERS = {'AES': b'#AES:', 'BLOWFISH': b':'}


def encrypt(message: bytes, key: bytes, algorithm: str) -> bytes:
    """
    Encrypt a message using a given algorithm and key.

    Args:
        message (bytes): The message to encrypt.
        key (bytes): The encryption key.
        algorithm (str): The encryption algorithm. Must be 'AES' or 'BLOWFISH'.

    Returns:
        bytes: The encrypted message.

    Raises:
        ValueError: If the algorithm is not valid.
    """
    algorithm = __validate_algorithm(algorithm)
    cipher, data = __get_cipher_and_data(message, key, algorithm)

    return cipher.encrypt(data)


def decrypt(message: bytes, key: bytes,  algorithm: str) -> bytes:
    """
    Decrypt a message using a given algorithm and key.

    Args:
        message (bytes): The message to decrypt.
        key (bytes): The decryption key.
        algorithm (str): The decryption algorithm. Must be 'AES' or 'BLOWFISH'.

    Returns:
        bytes: The decrypted message.

    Raises:
        ValueError: If the algorithm is not valid.
    """
    algorithm = __validate_algorithm(algorithm)
    cipher, data = __get_cipher_and_data(message, key, algorithm)

    return cipher.decrypt(data)


def encode(message: bytes) -> str:
    """
    Encode a message before encrypting it.

    This method adds a header with a hash, a counter and a checksum to the message,
    compresses it and adds padding.

    Args:
        message (bytes): The message to encode.

    Returns:
        str: The encoded message.
    """
    # Compose sec message
    payload = b'55555' + b'1234567891' + b':' + b'0227' + b':' + message
    message_hash = hashlib.md5(payload).hexdigest()
    payload = message_hash.encode() + payload
    # Compress
    payload = zlib.compress(payload)
    # Padding
    padding = (b'!' * (8 - extra if (extra := len(payload) % 8) > 0 else 8))

    return padding + payload


def decode(message: bytes) -> str:
    """
    Decode a decrypted message.

    This method removes the padding, decompresses and decodes the message.

    Args:
        message (bytes): The decrypted message.

    Returns:
        str: The decoded message.
    """
    padding = next((index for index, char in enumerate(
                    message) if char != 33), len(message))

    msg_remove_padding = message[padding:]
    msg_decompress = zlib.decompress(msg_remove_padding)

    return msg_decompress.decode('ISO-8859-1')


def pack(data, format_: str = "<I") -> bytes:
    """Pack data with a given header. Using Wazuh header by default.

    Args:
        data (int): Int number to pack
        format_ (str): Optional - Format used to pack data. Default "<I"

    Returns:
        (bytes) : Packed value
    """
    return struct.pack(format_, data)


def unpack(data, format_: str = "<I") -> bytes:
    """Unpack data with a given header. Using Wazuh header by default.

    Args:
        data (bytes): Binary data to unpack
        format_ (str): Optional - Format used to unpack data. Default "<I"

    Returns:
        int : Unpacked value
    """
    return struct.unpack(format_, data)[0]


def get_algorithm(message: bytes) -> Union[str, None]:
    """
    Get the encryption algorithm used in a message based on its header.

    Args:
        message (bytes): The encrypted message.

    Returns:
        Union[str, None]: The encryption algorithm name ('AES' or 'BLOWFISH')
                            or None if no header is found.
    """
    if ALGORITHM_HEADERS['AES'] in message:
        return 'AES'
    elif ALGORITHM_HEADERS['BLOWFISH'] in message:
        return 'BLOWFISH'


def get_agent_id(message: bytes) -> Union[str, None]:
    """
    Extracts the agent ID from a given Wazuh message.

    In Wazuh, the agent ID is sent within the message, enclosed between
    two exclamation marks '!'. Example: !001!: RestOfTheMsg...

    Args:
        message (bytes): The message from which to extract the agent ID.

    Returns:
        Union[str, None]: The ID as a string if it comes on the message. Otherwise None.
    """
    if b'!' not in message:
        return None

    # Get the agent ID from the message. Example: !001!
    start_index = message.find(b'!') + 1
    end_index = message.find(b'!', start_index)

    return message[start_index: end_index].decode()


def get_payload(message: bytes, algorithm: str) -> bytes:
    """
    Extracts the payload from a given Wazuh message.

    The payload is the part of the message that contains the actual data,
    after removing the encryption algorithm header.

    Args:
        message (bytes): The message from which to extract the payload.
        algorithm (str): The encryption algorithm used in the message. Must be 'AES' or 'BLOWFISH'.

    Returns:
        bytes: The extracted payload.

    Raises:
        ValueError: If the algorithm is not valid or the message encryption header is invalid.
    """
    algorithm = __validate_algorithm(algorithm)

    if algorithm == 'AES':
        start_index = message.find(ALGORITHM_HEADERS['AES'])
        end_index = start_index + 5
    elif algorithm == 'BLOWFISH':
        start_index = message.find(ALGORITHM_HEADERS['BLOWFISH'])
        end_index = start_index + 1

    if start_index == -1:
        raise ValueError('Invalid message encryption header.')

    return message[end_index:]


def get_encryption_key(id: str, name: str, key: str) -> bytes:
    """Generate an encryption key using agent metadata and a key.

    The encryption key is generated by combining the MD5 hashes of the agent name,
    agent ID, and the provided key.

    Args:
        id (str): The ID of the agent.
        name (str): The name of the agent.
        key (str): The encryption key.

    Returns:
        bytes: The generated encryption key as bytes.
    """
    first_hash = (hashlib.md5(hashlib.md5(name.encode()).hexdigest().encode() +
                                hashlib.md5(str(id).encode()).hexdigest().encode()
                                ).hexdigest().encode())[:15]
    second_hash = hashlib.md5(key.encode()).hexdigest().encode()

    return second_hash + first_hash


def set_algorithm_header(message: bytes, algorithm: str) -> bytes:
    """
    Adds an encryption algorithm header to a given Wazuh message.

    The header indicates which algorithm was used to encrypt the message.

    Args:
        message (bytes): The message to add the header to.
        algorithm (str): The encryption algorithm used in the message. Must be 'AES' or 'BLOWFISH'.

    Returns:
        bytes: The message with the added header.

    Raises:
        ValueError: If the algorithm is not valid.
    """
    algorithm = __validate_algorithm(algorithm)
    header = ALGORITHM_HEADERS[algorithm]

    return header + message

# Internal methods


def __get_cipher_and_data(payload: bytes, key: bytes, algorithm: str) -> Tuple[object, bytes]:
    """
    Creates a cipher object and prepares the payload for encryption or decryption.

    Args:
        payload (bytes): The payload to encrypt or decrypt.
        key (bytes): The encryption or decryption key.
        algorithm (str): The encryption or decryption algorithm.

    Returns:
        Tuple[object, bytes]: A tuple of the cipher object and the prepared payload.

    Raises:
        ValueError: If the algorithm is not valid.
    """
    algorithm = __validate_algorithm(algorithm)

    if algorithm == 'AES':
        cipher = AES.new(key[:32], AES.MODE_CBC, __AES_IV)
        payload = pad(payload, __BLOCK_SIZE)
    elif algorithm == 'BLOWFISH':
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, __BLOWFISH_IC)

    return cipher, payload


def __validate_algorithm(algorithm: str) -> str:
    """
    Validates an encryption or decryption algorithm.

    Args:
        algorithm (str): The encryption or decryption algorithm.

    Returns:
        str: The algorithm name in uppercase.

    Raises:
        ValueError: If the algorithm is not valid.
    """
    if not algorithm or algorithm.upper() not in ALGORITHM_HEADERS.keys():
        raise ValueError('Invalid encryption/decryption algorithm.')

    return algorithm.upper()
