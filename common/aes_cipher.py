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

# original_key = AESCipher.create_aes_key()  # This will be the AES key used for encryption/decryption
# cipher = AESCipher(original_key)
#
# # Encrypt a nonce (8 bytes) and a new AES key (32 bytes)
# nonce = urandom(8)  # Generate an 8-byte nonce
# new_aes_key = urandom(32)  # Simulate a new AES key to be sent
#
# # Encrypt both nonce and new_aes_key
# encrypted_nonce = cipher.encrypt(nonce)
# encrypted_aes_key = cipher.encrypt(new_aes_key)
#
# # Concatenate iv + encrypted_nonce + encrypted_aes_key
# message = cipher.iv + encrypted_nonce + encrypted_aes_key
#
# # Decryption process to verify
# decrypted_nonce, decrypted_aes_key = cipher.decrypt_message_format(message)
#
# # Verification
# nonce_match = nonce == decrypted_nonce
# aes_key_match = new_aes_key == decrypted_aes_key
#
# print(nonce_match, aes_key_match)

# # Generate a shared IV for both operations
# shared_iv = AESCipher.create_iv()
#
# # Initialize your AESCipher with the AES key and shared IV
# key_hex = AESCipher.create_aes_key()
# cipher_with_key = AESCipher(key_hex, shared_iv)
#
# # Encrypt data with the AES key
# data_to_encrypt = b'Hello, World!'
# encrypted_with_key = cipher_with_key.encrypt(data_to_encrypt)
# print(f"Encrypted with key: {encrypted_with_key.decode()}")
#
# # Decrypt data encrypted with the AES key
# decrypted_with_key = cipher_with_key.decrypt(encrypted_with_key)
# print(f"Decrypted with key: {decrypted_with_key}")
#
# nonce = b'sdelfkto'
# aes_new = AESCipher.create_aes_key().encode('utf-8')
# print(f"AES NEW --> {aes_new}")
#
# encrypted_with_key = cipher_with_key.encrypt(nonce)
# print(f"Encrypted NONCE with key: {encrypted_with_key.decode()}")
#
# # Decrypt data encrypted with the AES key
# decrypted_with_key = cipher_with_key.decrypt(encrypted_with_key)
# print(f"Decrypted NONCE with key: {decrypted_with_key}")
# print(f"AES MATCH ==> {nonce == decrypted_with_key}")
#
# encrypted_with_key = cipher_with_key.encrypt(aes_new)
# print(f"Encrypted AES NEW with key: {encrypted_with_key.decode()}")
#
# # Decrypt data encrypted with the AES key
# decrypted_with_key = cipher_with_key.decrypt(encrypted_with_key)
# print(f"Decrypted AES NEW with key: {decrypted_with_key}")
# print(f"AES MATCH ==> {aes_new == decrypted_with_key}")
