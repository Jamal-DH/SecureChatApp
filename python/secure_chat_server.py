# secure_chat_server.py

import socket
import threading
import logging
import time
from logging_config import setup_logging
from utils.tls_setup import ensure_cert_in_cert_dir, configure_tls_context
import os
import sys
import ssl

# Setup logging using the setup_logging function from logging_config
logger = setup_logging()

def start_server(port):
    """
    Starts the secure chat server on the specified port.
    Sets up TLS context, listens for incoming client connections,
    and handles message relaying between connected clients.
    
    Args:
        port (str): The port number on which the server will listen for incoming connections.
    """
    # Ensure that the server's certificate and key are present in the certificate directory
    cert_path, key_path = ensure_cert_in_cert_dir(
        cert_filename="server_cert.pem",
        key_filename="server_key.pem"
    )

    # Configure TLS context for the server
    logger.info("Configuring TLS context...")
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    tls_context.verify_mode = ssl.CERT_NONE  # Disable certificate verification (allow self-signed certificates)

    # Dictionaries to keep track of connected clients and their public keys
    clients = {}            # Maps client_id to client_socket
    client_public_keys = {} # Maps client_id to public_key_bytes
    client_addresses = {}   # Maps client_socket to client_address

    def handle_client(client_socket, client_id):
        """
        Handles communication with a connected client.
        Receives the client's public key, exchanges keys with the peer client,
        and relays messages between clients.
        
        Args:
            client_socket (ssl.SSLSocket): The SSL-wrapped socket connected to the client.
            client_id (str): A unique identifier for the client (e.g., "c1").
        """
        try:
            # Retrieve the client's address from the client_addresses dictionary
            client_address = client_addresses[client_socket]
            logger.info(f"Client {client_id} connected from {client_address}")

            # Receive the length of the client's public key (4 bytes, big-endian)
            key_length_bytes = client_socket.recv(4)
            if not key_length_bytes:
                raise Exception("Failed to receive public key length.")
            key_length = int.from_bytes(key_length_bytes, byteorder='big')

            # Receive the client's public key based on the received length
            client_public_key_bytes = b''
            while len(client_public_key_bytes) < key_length:
                packet = client_socket.recv(key_length - len(client_public_key_bytes))
                if not packet:
                    raise Exception("Failed to receive complete public key.")
                client_public_key_bytes += packet

            # Store the client's public key and socket in the respective dictionaries
            client_public_keys[client_id] = client_public_key_bytes
            clients[client_id] = client_socket

            # Wait until both clients have connected and exchanged public keys
            while len(client_public_keys) < 2:
                time.sleep(1)  # Sleep for a short duration to prevent busy waiting

            # Identify the peer client (the other client)
            peer_id = [cid for cid in client_public_keys if cid != client_id][0]
            peer_public_key_bytes = client_public_keys[peer_id]

            # Send the peer's public key to the current client
            data_to_send = peer_public_key_bytes
            data_length = len(data_to_send).to_bytes(4, byteorder='big')
            client_socket.sendall(data_length + data_to_send)

            logger.info(f"Sent peer's public key to client {client_id}")

            while True:
                # Read the message length (4 bytes, big-endian) from the client
                message_length_bytes = client_socket.recv(4)
                if not message_length_bytes:
                    break  # No more data; client has disconnected
                message_length = int.from_bytes(message_length_bytes, byteorder='big')

                # Receive the full message based on the length
                data = b''
                while len(data) < message_length:
                    packet = client_socket.recv(message_length - len(data))
                    if not packet:
                        break
                    data += packet
                if not data:
                    break  # No more data; client has disconnected

                # Extract the sender's client ID and the encrypted message
                try:
                    sender_client_id, encrypted_message = data.split(b':', 1)
                    logger.info(f"Relaying message from {sender_client_id.decode('utf-8')}")

                    # Extract IV (Initialization Vector), Tag, and Ciphertext from the encrypted message
                    if len(encrypted_message) < 28:
                        logger.error("Encrypted message is too short to contain IV and Tag.")
                        continue
                    iv = encrypted_message[:12]         # First 12 bytes for IV
                    tag = encrypted_message[12:28]      # Next 16 bytes for Tag
                    ciphertext = encrypted_message[28:] # Remaining bytes for Ciphertext

                    # Log the components in hexadecimal format for debugging
                    logger.info(f"IV (hex): {iv.hex()}")
                    logger.info(f"Tag (hex): {tag.hex()}")
                    logger.info(f"Ciphertext (hex): {ciphertext.hex()}")

                except Exception as e:
                    logger.error(f"Error parsing message from client: {e}")
                    continue  # Skip relaying this message due to parsing error

                # Relay the received message to all other connected clients
                for cid, sock in clients.items():
                    if sock != client_socket:
                        try:
                            # Send the message length and the data to the peer client
                            sock.sendall(message_length_bytes + data)
                        except Exception as e:
                            logger.error(f"Error sending message to {cid}: {e}")

        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            # Clean up resources when the client disconnects
            if client_id in clients:
                logger.info(f"Client {client_id} disconnected")
                del clients[client_id]
            if client_id in client_public_keys:
                del client_public_keys[client_id]
            client_socket.close()

    try:
        # Create a raw TCP socket
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of local addresses
        raw_socket.bind(('0.0.0.0', int(port)))  # Bind to all interfaces on the specified port
        raw_socket.listen(5)  # Listen for incoming connections with a backlog of 5

        # Wrap the raw socket with SSL/TLS for secure communication
        server_socket = tls_context.wrap_socket(
            raw_socket,
            server_side=True
        )

        logger.info(f"Server started on port {port}")

        client_id_counter = 1  # Counter to assign unique IDs to connected clients

        while True:
            try:
                # Accept a new client connection
                client_socket, client_address = server_socket.accept()
                client_id = f"c{client_id_counter}"  # Assign a unique client ID
                client_id_counter += 1
                client_addresses[client_socket] = client_address  # Store the client's address

                # Start a new thread to handle the connected client
                threading.Thread(target=handle_client, args=(client_socket, client_id), daemon=True).start()
            except KeyboardInterrupt:
                # Gracefully shut down the server on a keyboard interrupt (e.g., Ctrl+C)
                logger.info("Server is shutting down")
                for client in list(clients.values()):
                    client.close()  # Close all active client connections
                break
    except Exception as e:
        logger.error(f"Error starting server: {e}")

if __name__ == "__main__":
    """
    Entry point for the secure chat server application.
    Parses command-line arguments and starts the server.
    """
    if len(sys.argv) != 2:
        print("Usage: python secure_chat_server.py <port>")
        sys.exit(1)
    server_port = sys.argv[1]
    start_server(server_port)
