"""
Author: Erez Drutin
Date: 15.03.2024
Purpose: Construct an offline dictionary attack that demonstrated how one
can "crack" the user's password utilizing the nonce passed by the client to
the server using a list of commonly used passwords.
"""
from hashlib import sha256
from typing import Tuple
from attacks.pass_gen import generate_passwords
from common.aes_cipher import AESCipher
from attacks.consts import IV, NONCE, ENCRYPTED_NONCE, COMMON_PASSWORDS, \
    PASSWORD_VARIATIONS
from common.utils import enforce_len


def decrypt_nonce(password: str, iv: bytes, encrypted_nonce: bytes) -> bytes:
    """
    Decrypts the nonce using the given password and IV.
    @param password: A password to create the AES Cipher with.
    @param iv: An initialization vector to create the AES Cipher with.
    @param encrypted_nonce: The nonce to decrypt.
    @return: The decrypted nonce.
    """
    aes_key = sha256(enforce_len(password.encode('utf-8'), 255)).digest()
    cipher = AESCipher(key=aes_key.hex(), iv=iv)
    return cipher.decrypt(encrypted_nonce)


def attempt_decrypt_with_generated_passwords(
        encrypted_nonce: bytes, nonce: bytes, iv: bytes) -> Tuple[bool, str]:
    """
    Attempts to decrypt the nonce using generated passwords.
    @param encrypted_nonce: The nonce to decrypt.
    @param nonce: The original nonce.
    @param iv: An initialization vector to create the AES Cipher with.
    @return: A tuple of a boolean indicating success and the correct password.
    """
    password_generator = generate_passwords(COMMON_PASSWORDS,
                                            PASSWORD_VARIATIONS)
    for password in password_generator:
        decrypted_nonce = decrypt_nonce(password, iv, encrypted_nonce)
        if decrypted_nonce == nonce:
            return True, password
    return False, ''


def main():
    status, password = attempt_decrypt_with_generated_passwords(
        ENCRYPTED_NONCE, NONCE, IV)

    if not status:
        print(f"Was unable to breach into the system, client's password must "
              f"be strong.")
    else:
        print(f"Successfully breached the system! The client's password "
              f"is: {password}")


if __name__ == '__main__':
    main()
