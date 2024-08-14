import ssl
import subprocess
import os

def create_self_signed_cert(certfile, keyfile):
    """
    Creates a self-signed certificate using OpenSSL.

    Args:
    certfile (str): The path to the certificate file.
    keyfile (str): The path to the key file.
    """
    # Use the OpenSSL binary from the project's ssl directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(os.path.dirname(current_dir))
    openssl_bin = os.path.join(project_dir, 'ssl', 'OpenSSL-Win64', 'bin', 'openssl.exe')
    if not os.path.isfile(openssl_bin):
        raise FileNotFoundError(f"OpenSSL binary not found at {openssl_bin}")
    
    cmd = [
        openssl_bin, "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:2048", "-keyout", keyfile, "-out", certfile,
        "-subj", "/CN=localhost"
    ]
    subprocess.run(cmd, check=True)

def configure_tls_context(certfile, keyfile, purpose):
    """
    Configures a TLS context using the provided certificate and key files.

    Args:
    certfile (str): The path to the certificate file.
    keyfile (str): The path to the key file.
    purpose (ssl.Purpose): The purpose of the SSL context (CLIENT_AUTH or SERVER_AUTH).

    Returns:
    ssl.SSLContext: The configured SSL context.
    """
    context = ssl.create_default_context(purpose)
    context.load_cert_chain(certfile, keyfile)
    
    if purpose == ssl.Purpose.SERVER_AUTH:
        # Client-specific configuration to trust the self-signed certificate
        context.load_verify_locations(cafile=certfile)
    else:
        # Server-specific configuration to not verify client certificates (optional)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    return context

# Define the paths to the certificate and key files
certfile = "selfsigned.crt"
keyfile = "selfsigned.key"

# Create the self-signed certificate
create_self_signed_cert(certfile, keyfile)

# Example usage of configure_tls_context
tls_context = configure_tls_context(certfile, keyfile, ssl.Purpose.SERVER_AUTH)
