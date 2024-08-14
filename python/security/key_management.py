#key_managemant.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import logging

def generate_ecdh_keypair():
    try:
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        logging.info("ECDH key pair generated successfully")
        return private_key, public_key
    except Exception as e:
        logging.error(f"Key pair generation failed: {e}")
        return None, None

def derive_shared_key(private_key, peer_public_key_bytes):
    try:
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        logging.info("Shared key derived successfully")
        return derived_key
    except Exception as e:
        logging.error(f"Shared key derivation failed: {e}")
        return None
