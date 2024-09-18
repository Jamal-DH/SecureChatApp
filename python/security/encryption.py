import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

def encrypt_message(key, plaintext):
    iv = os.urandom(12)  # os.urandom is cryptographically secure
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    encrypted_message = base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')
    
    # Logging the IV, tag, ciphertext, and key
    logging.info(f"Encryption - Key: {key.hex()}, IV: {iv.hex()}, Tag: {encryptor.tag.hex()}, Ciphertext: {ciphertext.hex()}")
    
    return encrypted_message

def decrypt_message(key, encrypted_message):
    try:
        encrypted_message = base64.b64decode(encrypted_message)
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        
        # Logging the IV, tag, ciphertext, and key before decryption
        logging.info(f"Decryption - Key: {key.hex()}, IV: {iv.hex()}, Tag: {tag.hex()}, Ciphertext: {ciphertext.hex()}")
        
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        
        logging.info("Message decrypted successfully")
        return decrypted_message.decode('utf-8')
    except InvalidTag:
        logging.error("Invalid authentication tag")
        return None
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return None
