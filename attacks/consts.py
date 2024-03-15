"""
Author: Erez Drutin
Date: 15.03.2024
Purpose: Define constants that will be used in the attacks. Assuming we have
obtained them directly via the network logs.
Given the following server logs, we can extract IV + encrypted nonce:
2024-03-15 12:45:04,218 - root - DEBUG - IV: b'\x89p\xa1z\xfdm\x81\xc7\x80{\xb1^\x1c\xafyV'
2024-03-15 12:45:04,218 - root - DEBUG - Encrypted nonce: b'R\xaa\xb6\xd1k\xf5\xd1\xcdx>\xb0\xedn(\x90\xd1'
Similarly, we can extract the nonce from the client logs:
2024-03-15 12:44:35,321 - main - DEBUG - Created nonce: b'\xd4l]\xadBbJ!'
"""

IV = b'\x89p\xa1z\xfdm\x81\xc7\x80{\xb1^\x1c\xafyV'
ENCRYPTED_NONCE = b'R\xaa\xb6\xd1k\xf5\xd1\xcdx>\xb0\xedn(\x90\xd1'
NONCE = b'\xd4l]\xadBbJ!'

COMMON_PASSWORDS = ["password", "password123", "letmein", "qwerty",
                    "123456", "abc123", "admin", "welcome", "monkey",
                    "sunshine"]
PASSWORD_VARIATIONS = ["", "123", "1234", "12345", "123456", "!", "@", "#",
                       "$", "%", "^", "&", "*", "(", ")", "-", "_", "+",
                       "=", "/", "\\", "|", "[", "]", "{", "}", "<", ">"]
