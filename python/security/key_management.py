# key_management.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import logging
from typing import Tuple

# Configure logger for this module
logger = logging.getLogger('secure_chat.key_management')


def generate_ecdh_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generates an ECDH key pair using the SECP384R1 curve.

    :return: Tuple containing the private key and public key.
    """
    try:
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        logger.info("ECDH key pair generated successfully")
        return private_key, public_key
    except Exception as e:
        logger.error(f"Key pair generation failed: {e}")
        raise


def derive_shared_key(private_key: ec.EllipticCurvePrivateKey, peer_public_key_bytes: bytes) -> bytes:
    """
    Derives a shared secret using ECDH and then derives a symmetric key using HKDF.

    :param private_key: The client's private ECDH key.
    :param peer_public_key_bytes: The peer's public ECDH key in PEM format (bytes).
    :return: A derived symmetric key in bytes.
    """
    try:
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=None,  # In a real application, use a proper salt
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        logger.info("Shared key derived successfully")
        return derived_key
    except Exception as e:
        logger.error(f"Shared key derivation failed: {e}")
        raise
