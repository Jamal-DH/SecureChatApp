# security/encryption.py

import os
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Configure logger for this module
logger = logging.getLogger('secure_chat.encryption')


def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """
    Encrypts a plaintext message using AES-256-GCM.

    :param key: Symmetric key (bytes), must be 32 bytes for AES-256.
    :param plaintext: The message to encrypt (str).
    :return: Encrypted message as bytes (IV + Tag + Ciphertext).
    """
    try:
        iv = os.urandom(12)  # 96-bit nonce for GCM
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        encrypted_message = iv + encryptor.tag + ciphertext  # Concatenate IV, Tag, and Ciphertext
        
        logger.debug(f"Message encrypted successfully. IV: {iv.hex()}, Tag: {encryptor.tag.hex()}, Ciphertext Length: {len(ciphertext)} bytes")
        
        return encrypted_message  # Returns bytes
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise


def decrypt_message(key: bytes, encrypted_message: bytes) -> str:
    """
    Decrypts an encrypted message using AES-256-GCM.

    :param key: Symmetric key (bytes), must be 32 bytes for AES-256.
    :param encrypted_message: Encrypted message as bytes (IV + Tag + Ciphertext).
    :return: Decrypted plaintext message (str) or None if decryption fails.
    """
    try:
        if len(encrypted_message) < 28:
            # IV (12 bytes) + Tag (16 bytes) = 28 bytes minimum
            logger.error("Encrypted message is too short.")
            return None
        
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        
        logger.debug(f"Decryption initiated. IV: {iv.hex()}, Tag: {tag.hex()}, Ciphertext Length: {len(ciphertext)} bytes")
        
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        decrypted_message = decrypted_padded.decode('utf-8')
        
        logger.debug("Message decrypted successfully.")
        return decrypted_message
    except InvalidTag:
        logger.error("Invalid authentication tag. Decryption failed.")
        return None
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None
