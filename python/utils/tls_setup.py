import ssl
import subprocess
from pathlib import Path
import os
import logging

# Configure logging
#logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_self_signed_cert(certfile, keyfile):
    """
    Creates a self-signed certificate using the OpenSSL binary.

    Args:
        certfile (str or Path): The path to the certificate file.
        keyfile (str or Path): The path to the key file.
    """
    # Convert to Path objects if they aren't already
    certfile = Path(certfile)
    keyfile = Path(keyfile)

    # Determine the project root directory 
    current_dir = Path(__file__).resolve().parent
    project_root = current_dir.parent.parent  # Adjust based on actual script location

    # Path to the OpenSSL binary
    openssl_bin = project_root / 'ssl' / 'OpenSSL-Win64' / 'bin' / 'openssl.exe'

    if not openssl_bin.is_file():
        logging.error(f"OpenSSL binary not found at {openssl_bin}")
        raise FileNotFoundError(f"OpenSSL binary not found at {openssl_bin}")

    # Ensure the certfile and keyfile directories exist
    certfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(openssl_bin),
        "req",
        "-x509",
        "-nodes",
        "-days",
        "365",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(keyfile),
        "-out",
        str(certfile),
        "-subj",
        "/CN=localhost"
    ]

    logging.info("Generating self-signed certificate and key...")
    try:
        subprocess.run(cmd, check=True)
        logging.info(f"Self-signed certificate created at {certfile} and key at {keyfile}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"An error occurred while creating the certificate: {e}")
        raise

def configure_tls_context(certfile, keyfile, purpose):
    """
    Configures a TLS context using the provided certificate and key files.

    Args:
        certfile (str or Path): The path to the certificate file.
        keyfile (str or Path): The path to the key file.
        purpose (ssl.Purpose): The purpose of the SSL context (CLIENT_AUTH or SERVER_AUTH).

    Returns:
        ssl.SSLContext: The configured SSL context.
    """
    # Convert to Path objects if they aren't already
    certfile = Path(certfile)
    keyfile = Path(keyfile)

    # Verify that certfile and keyfile exist
    if not certfile.is_file():
        logging.error(f"Certificate file not found: {certfile}")
        raise FileNotFoundError(f"Certificate file not found: {certfile}")

    if not keyfile.is_file():
        logging.error(f"Key file not found: {keyfile}")
        raise FileNotFoundError(f"Key file not found: {keyfile}")

    try:
        context = ssl.create_default_context(purpose)
        context.load_cert_chain(certfile, keyfile)
        logging.info("Loaded certificate and key successfully.")

        if purpose == ssl.Purpose.SERVER_AUTH:
            # Client-specific configuration to trust the self-signed certificate
            context.load_verify_locations(cafile=certfile)
            logging.info("Loaded verify locations for server authentication.")
        else:
            # Server-specific configuration to not verify client certificates (optional)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logging.info("Configured context for client authentication without verification.")

        return context
    except ssl.SSLError as e:
        logging.error(f"SSL error occurred while loading cert and key: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during TLS configuration: {e}")
        raise

if __name__ == "__main__":
    # Define the paths to the certificate and key files
    # It's recommended to place these in the 'config' directory
    project_root = Path(__file__).resolve().parent.parent  # Adjust based on actual script location
    config_dir = project_root / 'config'
    certfile = config_dir / "cert.pem"       # Changed from selfsigned.crt to cert.pem
    keyfile = config_dir / "key.pem"         # Changed from selfsigned.key to key.pem

    # Create the self-signed certificate
    create_self_signed_cert(certfile, keyfile)

    # Example usage of configure_tls_context
    try:
        tls_context = configure_tls_context(certfile, keyfile, ssl.Purpose.SERVER_AUTH)
        logging.info("TLS context configured successfully.")
    except Exception as e:
        logging.error(f"Failed to configure TLS context: {e}")
