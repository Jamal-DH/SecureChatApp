import socket
import threading
import logging
from security.encryption import encrypt_message, decrypt_message
from security.key_management import generate_ecdh_keypair, derive_shared_key
from cryptography.hazmat.primitives import serialization
from logging_config import setup_logging
from utils.tls_setup import create_self_signed_cert, configure_tls_context
import os
import sys
import ssl

# Setup logging
logger = setup_logging()

# Define paths to certificate and key files
certfile = 'cert.pem'
keyfile = 'key.pem'

# Create self-signed certificate if not already present
if not os.path.exists(certfile) or not os.path.exists(keyfile):
    logger.info("Creating self-signed certificate and key...")
    create_self_signed_cert(certfile, keyfile)

# Configure TLS context for the server
logger.info("Configuring TLS context...")
tls_context = configure_tls_context(certfile, keyfile, ssl.Purpose.CLIENT_AUTH)

clients = {}
client_keys = {}

private_key, public_key = generate_ecdh_keypair()

client_id_counter = 1

def broadcast(message, sender_socket=None):
    for client in list(clients.keys()):
        if client != sender_socket:
            try:
                encrypted_message = encrypt_message(client_keys[client], message)
                logger.info(f"Relaying encrypted message: {encrypted_message}")
                client.send(encrypted_message.encode('utf-8'))
            except Exception as e:
                logger.error(f"Error sending message: {e}")
                client.close()
                if client in clients:
                    del clients[client]
                    del client_keys[client]

def handle_client(client_socket, client_id):
    try:
        logger.info(f"Client {client_id} connected from {client_socket.getpeername()}")
        client_socket.send(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        client_pub_key = client_socket.recv(4096)
        shared_key = derive_shared_key(private_key, client_pub_key)
        client_keys[client_socket] = shared_key
        clients[client_socket] = client_id

        # Log the derived shared key for troubleshooting
        logger.info(f"Derived shared key for client {client_id}: {shared_key.hex()}")

        while True:
            encrypted_message = client_socket.recv(4096).decode('utf-8')
            if not encrypted_message:
                break
            message = decrypt_message(shared_key, encrypted_message)
            if message:
                broadcast(f"{client_id}: {message}", client_socket)
            else:
                logger.error("Failed to decrypt the message")
    except Exception as e:
        logger.error(f"Error handling client {client_id}: {e}")
    finally:
        if client_socket in clients:
            logger.info(f"Client {client_id} disconnected")
            disconnect_message = f"Client {client_id} has left the chat."
            broadcast(disconnect_message, client_socket)
            del clients[client_socket]
            del client_keys[client_socket]
        client_socket.close()

def start_server(port):
    global client_id_counter
    try:
        server_socket = tls_context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_side=True)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', int(port)))
        server_socket.listen(5)
        logger.info(f"Server started on port {port}")

        while True:
            try:
                client_socket, _ = server_socket.accept()
                client_id = f"c{client_id_counter}"
                client_id_counter += 1
                threading.Thread(target=handle_client, args=(client_socket, client_id)).start()
            except KeyboardInterrupt:
                logger.info("Server is shutting down")
                for client in list(clients.keys()):
                    disconnect_message = "Server is shutting down."
                    broadcast(disconnect_message)
                    client.close()
                break
    except Exception as e:
        logger.error(f"Error starting server: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python secure_chat_server.py <port>")
        sys.exit(1)
    server_port = sys.argv[1]
    start_server(server_port)
