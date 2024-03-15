import hashlib
from os import urandom
from Crypto.Cipher import AES
from typing import Tuple


class AESCipher:
    def __init__(self, key: str, iv: bytes = None,
                 block_size: int = AES.block_size):
        self.block_size = block_size
        self.key = hashlib.sha256(key.encode()).digest()
        self.iv = iv if iv is not None else AESCipher.create_iv()

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypts data using AES-256-CBC with a predefined IV.
        @param data: Data in bytes to encrypt.
        @return: Encrypted data, base64-encoded.
        """
        padded_data = self._pad(data)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(padded_data)
        return encrypted

    def decrypt(self, enc: bytes) -> bytes:
        """
        Decrypts an encrypted string encoded in base64 using AES-256-CBC
        with a predefined IV.
        @param enc: An encrypted data encoded in base64.
        @return: The decrypted data in bytes.
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(enc)
        return self.unpad(decrypted)

    def _pad(self, data: bytes) -> bytes:
        """
        Pads the data to be a multiple of the block size (using PKCS#7).
        @param data: Data in bytes to pad.
        @return: The padded data in bytes.
        """
        padding = self.block_size - len(data) % self.block_size
        return data + bytes([padding] * padding)

    @staticmethod
    def unpad(data: bytes) -> bytes:
        """
        Removes the padding from the data.
        @param data: Padded data in bytes.
        @return: The original data without padding.
        """
        return data[:-data[-1]]

    @staticmethod
    def create_aes_key() -> str:
        """Creates a new AES 32 bytes key and returns it as a string."""
        return urandom(32).hex()

    @staticmethod
    def create_iv() -> bytes:
        """Creates a new IV for AES encryption."""
        return urandom(AES.block_size)

    def decrypt_custom_(self, message: bytes) -> Tuple[bytes, bytes]:
        iv = message[:16]
        encrypted_nonce = message[16:32]
        encrypted_aes = message[32:80]

        self.iv = iv  # Set the IV to what was used for this message
        decrypted_nonce = self.decrypt(encrypted_nonce)
        decrypted_aes = self.decrypt(encrypted_aes)

        return decrypted_nonce, decrypted_aes
