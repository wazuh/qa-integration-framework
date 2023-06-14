from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad


class Cipher:
    """Algorithm to perform encryption/decryption of manager-agent secure messages:
    https://documentation.wazuh.com/current/development/message-format.html#secure-message-format.
    """

    def __init__(self, data: bytes, key: bytes) -> None:
        self.block_size = 16
        self.data = data
        self.blowfish_key = key
        self.aes_key = key[:32]
        self.aes_iv = b'FEDCBA0987654321'
        self.blowfish_iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'

    def encrypt_aes(self) -> bytes:
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        return cipher.encrypt(pad(self.data, self.block_size))

    def decrypt_aes(self) -> bytes:
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        return cipher.decrypt(pad(self.data, self.block_size))

    def encrypt_blowfish(self) -> bytes:
        cipher = Blowfish.new(self.blowfish_key, Blowfish.MODE_CBC, self.blowfish_iv)
        return cipher.encrypt(self.data)

    def decrypt_blowfish(self) -> bytes:
        cipher = Blowfish.new(self.blowfish_key, Blowfish.MODE_CBC, self.blowfish_iv)
        return cipher.decrypt(self.data)
    
    @staticmethod
    def get_encrypted_payload(message: bytes) -> str:
        if (index := message.find(b'#AES:')) is not -1:
            # AES encryption is used
            encrypted_data = message[index + len(b'#AES:'):]
        elif (index := message.find(b':')) is not -1:
            # Blowfish encryption is used
            encrypted_data = message[index + 1:]
        else:
            raise ValueError('Message encryption is not valid.')

        return encrypted_data
