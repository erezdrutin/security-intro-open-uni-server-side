import base64
import hashlib
from os import urandom
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher:
    def __init__(self, key: str, block_size: int = AES.block_size):
        self.block_size = block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw: str) -> bytes:
        """
        Encrypts a plaintext string using AES-256-CBC.
        @param raw: A plaintext string to encrypt
        @return: The encrypted data encoded in base64.
        """
        padded_raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(padded_raw.encode()))

    def decrypt(self, enc: bytes) -> str:
        """
        Decrypts an encrypted string encoded in base64 using AES-256-CBC.
        @param enc: An encrypted data encoded in base64.
        @return: The decrypted plaintext string.
        """
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher.unpad(cipher.decrypt(enc[AES.block_size:])).decode(
            'utf-8')

    def _pad(self, s: str) -> str:
        """
        Pads the plaintext to be a multiple of the block size (using PKCS#7).
        @param s: A plaintext string to pad.
        @return: The padded plaintext string.
        """
        padding = self.block_size - len(s) % self.block_size
        return s + padding * chr(padding)

    @staticmethod
    def unpad(s: bytes) -> bytes:
        """
        Removes the padding from a plaintext string.
        @param s: A padded plaintext string.
        @return: The original plaintext string without padding.
        """
        return s[:-s[-1]]

    @staticmethod
    def create_aes_key() -> str:
        """ Creates a new AES 32 bytes key and returns it as a string. """
        return urandom(32).hex()


# # Initialize your AESCipher with the hexadecimal string
# key_hex = AESCipher.create_aes_key()
# cipher = AESCipher(key_hex)
#
# # Encrypt and decrypt a message
# encrypted = cipher.encrypt('Hello, World!')
# print(f"Encrypted: {encrypted}")
#
# decrypted = cipher.decrypt(encrypted)
# print(f"Decrypted: {decrypted}")