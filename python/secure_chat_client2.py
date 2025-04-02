# secure_chat_client1.py

import os
import sys
import time
import ssl
import socket
import threading
import logging
import requests
import paramiko
import hashlib
import customtkinter as ctk  # Import CustomTkinter for enhanced GUI
from tkinter import messagebox, filedialog, Menu
from cryptography.hazmat.primitives import serialization
from security.encryption import encrypt_message, decrypt_message
from security.key_management import generate_ecdh_keypair, derive_shared_key
from logging_config import setup_logging
from utils.email_alert import get_system_info, format_email_body, send_email_alert
from utils.tls_setup import ensure_cert_in_cert_dir, configure_tls_context
from file_shredder import open_shredding_menu
from messages_enc_dec import main_screen
from Steganography import SteganographyApp
from usb_auth_handle import authenticate_usb
from glitch import run_glitch_effect_tkinter

# Configuration Constants
MAX_ATTEMPTS = 5        # Maximum number of authentication attempts allowed
LOCKOUT_DURATION = 120  # Duration (in seconds) to lock out after exceeding max attempts (2 minutes)

# Setup logging using the setup_logging function from logging_config
logger = setup_logging()

# Configure the appearance mode and color theme for CustomTkinter
ctk.set_appearance_mode("dark")         # Options: "dark", "light", "system"
ctk.set_default_color_theme("dark-blue")  # Options: "blue", "green", "dark-blue"

server_cert_path = os.path.join(os.path.dirname(__file__), "utils", "cert", "server_cert.pem")
class ChatClient:
    """
    Represents the secure chat client application.
    Handles authentication, secure connection setup, message encryption/decryption,
    file transfers, and user interactions through the GUI.
    """
    def __init__(self, master, host, server_port, client_port, client_id, position):
        """
        Initializes the ChatClient with necessary configurations and sets up the authentication UI.

        Args:
            master (ctk.CTk): The root window.
            host (str): The server's hostname or IP address.
            server_port (str): The port number of the server.
            client_port (str): The port number for the client.
            client_id (str): Identifier for the client (e.g., "c1").
            position (tuple): The (x, y) position for the window on the screen.
        """
        self.master = master
        self.host = host
        self.server_port = server_port
        self.client_port = client_port
        self.client_id = client_id
        self.private_key, self.public_key = generate_ecdh_keypair()  # Generate ECDH key pair
        self.peer_public_key = None
        self.shared_key = None
        self.ssh_client = None
        self.client_socket = None
        self.failed_attempts = 0
        self.lockout_time = 0

        # Configure the main window
        self.master.geometry("750x230")          # Set window size
        self.master.title("Authentication Key")  # Set window title

        # Create the authentication frame
        self.auth_frame = ctk.CTkFrame(self.master, fg_color="#252525")
        self.auth_frame.pack(fill="both", expand=True)

        # Label to display authentication error
        self.error_label = ctk.CTkLabel(
            self.auth_frame,
            text="ERROR: Authentication Failed",
            font=("Segoe UI", 22, "bold"),
            fg_color="#252525",
            text_color="red"
        )
        self.error_label.pack(pady=(10, 0))

        # Label with instructions for authentication
        self.auth_label = ctk.CTkLabel(
            self.auth_frame,
            text="USB Not Detected or Authentication Failed. Please Insert Your USB and Click 'Try Again'.",
            font=("Segoe UI", 19),
            fg_color="#252525",
            text_color="white",
            wraplength=430
        )
        self.auth_label.pack(pady=10)

        # "Try Again" button for re-attempting authentication
        self.try_again_button = ctk.CTkButton(
            self.auth_frame,
            text="Try Again",
            command=self.try_authenticate,
            font=("Segoe UI Bold", 13),
            fg_color="#255325",
            text_color="white"
        )
        self.try_again_button.pack(pady=20)

        # Label to display remaining authentication attempts
        self.auth_attempts_label = ctk.CTkLabel(
            self.auth_frame,
            text="",
            fg_color="#252525",
            text_color="red"
        )
        self.auth_attempts_label.pack(pady=5)

        # Perform the initial authentication attempt
        self.initial_authentication()

    def initial_authentication(self):
        """
        Performs the initial USB authentication attempt when the client starts.
        If authentication is successful, proceeds to start the chat client.
        Otherwise, prompts the user to try again.
        """
        try:
            if authenticate_usb():
                self.auth_frame.pack_forget()  # Hide the authentication frame
                self.start_chat_client()        # Proceed to start the chat client
            else:
                self.auth_label.configure(
                    text="USB not detected or authentication failed. Please insert your USB and click 'Try Again'."
                )
        except Exception as e:
            # Display an error message if an exception occurs during authentication
            messagebox.showerror("Authentication Error", f"An error occurred during initial authentication: {e}")

    def try_authenticate(self):
        """
        Handles the logic for re-attempting USB authentication when the "Try Again" button is clicked.
        Implements lockout after exceeding maximum authentication attempts.
        Sends email alerts and triggers glitch effects upon lockout.
        """
        # Check if the lockout period is active
        if self.lockout_time > 0 and time.time() < self.lockout_time:
            remaining_time = int(self.lockout_time - time.time())
            messagebox.showwarning(
                "Authentication Locked",
                f"Too many failed attempts. Please try again in {remaining_time // 60} minutes and {remaining_time % 60} seconds."
            )
            return

        try:
            if authenticate_usb():
                self.auth_frame.pack_forget()  # Hide the authentication frame
                self.start_chat_client()        # Proceed to start the chat client
            else:
                self.failed_attempts += 1
                remaining_attempts = max(0, MAX_ATTEMPTS - self.failed_attempts)
                self.auth_attempts_label.configure(text=f"Authentication failed. Attempts left: {remaining_attempts}")

                if remaining_attempts > 0:
                    # Inform the user about the failed authentication attempt
                    messagebox.showerror(
                        "Authentication Failed",
                        f"Invalid USB authentication data. Attempts remaining: {remaining_attempts}."
                    )
                else:
                    # Disable the "Try Again" button after reaching maximum attempts
                    self.try_again_button.configure(state="disabled")

                    # Send an email alert about the failed authentication attempts
                    system_info = get_system_info()
                    subject = "USB Authentication Failed"
                    email_body, logo_data, icon_data = format_email_body(system_info, MAX_ATTEMPTS)
                    to_email = "jzororonoro@gmail.com"
                    send_email_alert(subject, email_body, to_email, logo_data)

                    # Trigger glitch effect as a security measure
                    self.run_glitch_effect()

                    # Set the lockout time to prevent further attempts for the specified duration
                    self.lockout_time = time.time() + LOCKOUT_DURATION
                    messagebox.showerror(
                        "Authentication Locked",
                        f"Too many failed attempts. Locked out for {LOCKOUT_DURATION // 60} minutes."
                    )

                    # Reset the failed attempts counter after locking out
                    self.failed_attempts = 0
        except FileNotFoundError as e:
            # Handle case where USB authentication script is not found
            messagebox.showerror("USB Error", f"USB script not found: {e}")
        except Exception as e:
            # Handle any other exceptions during authentication
            messagebox.showerror("Authentication Error", f"An error occurred during authentication: {e}")

    def run_glitch_effect(self):
        """
        Executes a glitch effect in the GUI to indicate a security breach or failed authentication.
        """
        try:
            # Run the glitch effect in a new Toplevel window
            run_glitch_effect_tkinter()
            logging.info("Glitch effect executed.")
        except Exception as e:
            # Log any errors that occur while attempting to run the glitch effect
            logging.error(f"Failed to execute glitch effect: {e}")

    def start_chat_client(self):
        """
        Establishes a secure connection to the server, exchanges public keys,
        derives a shared key for encryption, and sets up the chat client GUI.
        """
        # Create self-signed certificates if they do not exist
        client_cert, client_key = ensure_cert_in_cert_dir(
            cert_filename="client_cert.pem",
            key_filename="client_key.pem"
        )

        # Path to the server's certificate
        server_cert = os.path.join(os.path.dirname(__file__), "utils", "cert", "server_cert.pem")
        logging.info("Configuring TLS context for client...")
        tls_context = configure_tls_context(
            certfile=client_cert,
            keyfile=client_key,
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=server_cert
        )

        self.tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        #new
        #load a CA file that signed your server certificate
        
        self.tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.tls_context.verify_mode = ssl.CERT_REQUIRED  # <--- MUST DO
        self.tls_context.check_hostname = True            # <--- Usually recommended
        self.tls_context.load_verify_locations(cafile=server_cert) 
        # Disable certificate verification to allow self-signed certificates
        #self.tls_context.check_hostname = False
        #self.tls_context.verify_mode = ssl.CERT_NONE

        try:
            # Create a raw socket and bind to the specified client port
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.client_port:
                raw_socket.bind(('0.0.0.0', int(self.client_port)))
                logger.info(f"Client socket bound to port {self.client_port}")
            else:
                raw_socket.bind(('0.0.0.0', 0))  # Bind to any available port

            # Wrap the socket with SSL for secure communication
            self.client_socket = self.tls_context.wrap_socket(
                raw_socket,
                server_hostname=self.host
            )

            # Connect to the server
            self.client_socket.connect((self.host, int(self.server_port)))
            logger.info(f"Connected to server on port {self.server_port} from client port {self.client_port}")
            """  
            # --- LOG THE SERVER CERT (check it is valid) ---
            server_cert_bin = self.client_socket.getpeercert(binary_form=True)
            if not server_cert_bin:
                logger.warning("No server certificate received or certificate is empty.")
            else:
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives import hashes

                    cert = x509.load_der_x509_certificate(server_cert_bin, default_backend())
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                    not_before = cert.not_valid_before
                    not_after  = cert.not_valid_after

                    logger.info("=== Server Certificate ===")
                    logger.info(f" Subject: {subject}")
                    logger.info(f" Issuer:  {issuer}")
                    logger.info(f" SHA-256 Fingerprint: {fingerprint}")
                    logger.info(f" Validity: {not_before} to {not_after}")
                except Exception as e:
                    logger.error(f"Error parsing server certificate: {e}")
            # --- END LOG ---
            """
            # Exchange public keys with the server for key agreement
            # Send our public key length and public key
            public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_length = len(public_key_bytes).to_bytes(4, byteorder='big')
            self.client_socket.sendall(public_key_length + public_key_bytes)

            # Receive peer's public key length and public key
            data_length_bytes = self.client_socket.recv(4)
            if not data_length_bytes:
                raise Exception("Failed to receive data length.")
            data_length = int.from_bytes(data_length_bytes, byteorder='big')

            data = b''
            while len(data) < data_length:
                packet = self.client_socket.recv(data_length - len(data))
                if not packet:
                    raise Exception("Failed to receive peer's public key.")
                data += packet

            # Deserialize the peer's public key
            peer_public_key_bytes = data
            self.peer_public_key = serialization.load_pem_public_key(
                peer_public_key_bytes
            )

            # Use fixed salt and info for key derivation
            salt = b'unique_salt_value'
            info = b'handshake data'

            # Derive the shared key using ECDH
            self.shared_key = derive_shared_key(self.private_key, peer_public_key_bytes, salt, info)
            logger.info(f"Derived shared key for client {self.client_id}")

            # Log shared key hash for debugging purposes
            shared_key_hash = hashlib.sha256(self.shared_key).hexdigest()
            logger.debug(f"Shared key hash for client {self.client_id}: {shared_key_hash}")

            # Update the window title and size for the chat interface
            self.master.title(f"Secure Chat Client {self.client_id}")
            self.master.geometry("600x680")
            self.master.configure(fg_color="#1a1a1a")
            self.master.geometry(f'+{position[0]}+{position[1]}')  # Set window position

            # Create the menu bar and chat widgets
            self.create_menu_bar()
            self.create_widgets()

            # Start a thread to listen for incoming messages
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()

        except Exception as e:
            # Handle any exceptions that occur during connection setup
            logger.error(f"Unable to connect to server: {e}")
            messagebox.showerror("Connection Error", f"Unable to connect to server: {e}")
            self.master.quit()

    def check_ip_address(self):
        """
        Retrieves and displays the current public IP address of the client using an external API.
        """
        try:
            # Send a GET request to retrieve the public IP address
            response = requests.get('https://api64.ipify.org?format=json')
            response.raise_for_status()  # Raise an exception for HTTP errors
            ip_info = response.json()
            public_ip = ip_info.get('ip', 'Unknown IP')
            messagebox.showinfo("IP Address", f"Current IP Address: {public_ip}")
        except requests.exceptions.RequestException as e:
            # Handle any exceptions that occur during the API request
            messagebox.showerror("Error", f"Failed to retrieve IP Address: {e}")

    def create_menu_bar(self):
        """
        Creates the menu bar with "Tools" and "Help" menus, adding various functionalities.
        """
        menubar = Menu(self.master, tearoff=0)

        # Tools Menu
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Encrypt/Decrypt", command=self.open_encryption_tool)
        tools_menu.add_command(label="Send File", command=self.open_file_transfer_dialog)
        tools_menu.add_command(label="Steganography Tool", command=self.open_steganography_tool)
        tools_menu.add_command(label="Shredding", command=self.open_shredding_menu)
        tools_menu.add_command(label="Check IP Address", command=self.check_ip_address)
        tools_menu.add_separator()
        tools_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # Help Menu
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about_info)
        menubar.add_cascade(label="Help", menu=help_menu)

        # Configure the menu bar in the main window
        self.master.config(menu=menubar)

    def show_about_info(self):
        """
        Displays an "About" dialog with information about the chat client.
        """
        messagebox.showinfo("About", "Advanced Secure Chat Client\nVersion 1.0\n\nDeveloped by: JAMAL_DH")

    def open_encryption_tool(self):
        """
        Opens the encryption/decryption tool GUI.
        """
        main_screen()

    def open_steganography_tool(self):
        """
        Opens the steganography tool GUI.
        """
        steganography_window = ctk.CTkToplevel(self.master)
        SteganographyApp(steganography_window)

    def open_shredding_menu(self):
        """
        Opens the file shredding menu for secure deletion of files.
        """
        open_shredding_menu(self.master)

    def open_status_window(self):
        """
        Opens the status window to display real-time status information.
        (Functionality commented out for future implementation.)
        """
        # self.status_monitor.start()
        # status_window = StatusWindow(self.master, self.status_monitor)
        pass

    def handle_alert(self, alert):
        """
        Handles real-time alerts by displaying pop-up notifications to the user.

        Args:
            alert (dict): Dictionary containing alert details, including 'type' and 'message'.
        """
        alert_type = alert.get('type', 'Alert')
        message = alert.get('message', 'An alert has been triggered.')
        # Display the alert in a pop-up message box
        messagebox.showwarning(f"{alert_type} Alert", message)

    def open_file_transfer_dialog(self):
        """
        Opens a file dialog for the user to select a file to send via SFTP.
        """
        file_path = filedialog.askopenfilename(title="Select a file to send")

        if file_path:
            if os.path.exists(file_path):
                absolute_file_path = os.path.abspath(file_path)
                logging.info(f"File selected: {absolute_file_path}")
                self.send_file_via_sftp(absolute_file_path)
            else:
                logging.error(f"File does not exist: {file_path}")
                messagebox.showerror("File Not Found", f"File not found: {file_path}")

    def send_file_via_sftp(self, file_path):
        """
        Sends a selected file to the server using SFTP (Secure File Transfer Protocol).

        Args:
            file_path (str): The absolute path of the file to be sent.
        """
        try:
            # Ensure SSH client is initialized and connected
            self.setup_ssh_client()

            absolute_file_path = os.path.abspath(file_path)
            logging.info(f"Attempting to send file from path: {absolute_file_path}")

            if not os.path.exists(absolute_file_path):
                logging.error(f"File does not exist: {absolute_file_path}")
                raise FileNotFoundError(f"File not found: {absolute_file_path}")

            if self.ssh_client is None:
                raise Exception("SSH client is not connected. Cannot establish SFTP session.")

            # Open a new SFTP session for file transfer
            with self.ssh_client.open_sftp() as sftp:
                home_dir = sftp.normalize('.')
                remote_dir = os.path.join(home_dir, 'received_files')
                remote_path = os.path.join(remote_dir, os.path.basename(absolute_file_path))

                try:
                    sftp.chdir(remote_dir)
                    logging.info(f"Remote directory {remote_dir} exists.")
                except IOError:
                    # Remote directory does not exist; attempt to create it
                    logging.warning(f"Remote directory {remote_dir} does not exist. Attempting to create it.")
                    sftp.mkdir(remote_dir)
                    sftp.chdir(remote_dir)
                    logging.info(f"Successfully created and changed to remote directory {remote_dir}.")

                # Upload the file to the remote directory
                sftp.put(absolute_file_path, remote_path)
                logging.info(f"File '{absolute_file_path}' sent successfully via SFTP to '{remote_path}'.")
                self.display_message(f"File '{absolute_file_path}' sent successfully via SFTP to '{remote_path}'.")

        except FileNotFoundError as fnf_error:
            # Handle case where the file is not found
            logging.error(f"File not found error: {fnf_error}")
            messagebox.showerror("File Transfer Error", f"File not found: {fnf_error}")
        except Exception as e:
            # Handle any other exceptions during file transfer
            logging.error(f"Failed to send file via SFTP: {e}")
            messagebox.showerror("File Transfer Error", f"Failed to send file via SFTP: {e}")
        finally:
            # Ensure the SSH connection is closed after the transfer
            if self.ssh_client:
                self.ssh_client.close()
                self.ssh_client = None
                logging.info("SSH connection closed.")

    def setup_ssh_client(self):
        """
        Sets up and establishes an SSH client connection using Paramiko.
        Retrieves SSH credentials from environment variables.

        Raises:
            ValueError: If SSH_USERNAME or SSH_PASSWORD environment variables are not set.
            paramiko.AuthenticationException: If SSH authentication fails.
            Exception: For any other errors during SSH connection setup.
        """
        if not self.ssh_client:
            try:
                username = os.getenv('SSH_USERNAME')  # Retrieve SSH username from environment variable
                password = os.getenv('SSH_PASSWORD')  # Retrieve SSH password from environment variable

                if not username or not password:
                    raise ValueError("SSH_USERNAME and SSH_PASSWORD environment variables must be set.")

                # Initialize the SSH client
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.load_system_host_keys()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Establish SSH connection to the server
                self.ssh_client.connect(
                    self.host,
                    port=22,
                    username=username,
                    password=password
                )
                logging.info("SSH connection established.")
            except paramiko.AuthenticationException as auth_error:
                # Handle SSH authentication failures
                logging.error(f"Authentication failed: {auth_error}")
                messagebox.showerror("SSH Authentication Error", f"Authentication failed: {auth_error}")
            except Exception as e:
                # Handle any other exceptions during SSH connection setup
                logging.error(f"Failed to establish SSH connection: {e}")
                messagebox.showerror("SSH Connection Error", f"Failed to connect to SSH server: {e}")
                self.ssh_client = None

    def create_widgets(self):
        """
        Creates and arranges the chat interface widgets, including labels, textboxes, and buttons.
        """
        # Header Label
        self.labelHead = ctk.CTkLabel(
            self.master,
            text=f"Secure Chat Client {self.client_id}",
            font=("Courier New", 20, "bold"),
            fg_color="#1a1a1a",
            text_color="#5F87AF"
        )
        self.labelHead.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        # Frame for the conversation textbox with border
        self.textbox_border_frame = ctk.CTkFrame(
            self.master,
            fg_color="#3A506B",
            corner_radius=0,
            border_width=1
        )
        self.textbox_border_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        # Textbox to display conversation
        self.textCons = ctk.CTkTextbox(
            self.textbox_border_frame,
            fg_color="#1a1a1a",
            text_color="#00FF00",
            font=("Courier New", 18),
            padx=5,
            pady=5
        )
        self.textCons.pack(fill="both", expand=True, padx=5, pady=5)
        self.textCons.configure(state="disabled")  # Disable editing by the user

        # Entry widget for typing messages
        self.entryMsg = ctk.CTkEntry(
            self.master,
            fg_color="#262626",
            text_color="#00FF00",
            font=("Helvetica", 18)
        )
        self.entryMsg.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.entryMsg.focus()  # Set focus to the message entry field

        # "Send" button to send messages
        self.buttonMsg = ctk.CTkButton(
            self.master,
            text="Send",
            font=("Courier New", 12, "bold"),
            fg_color="#8A9BA8",
            text_color="#1a1a1a",
            command=self.send_message
        )
        self.buttonMsg.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        # Configure grid weights for responsive resizing
        self.master.grid_rowconfigure(1, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=0)

    def send_message(self, event=None):
        """
        Sends an encrypted message to the server when the "Send" button is clicked.

        Args:
            event: The event that triggered this function (optional).
        """
        message = self.entryMsg.get()
        if message.strip():
            try:
                # Encrypt the message using the shared key
                encrypted_message = encrypt_message(self.shared_key, message)
                # Prepare the message with the sender's ID
                message_to_send = self.client_id.encode('utf-8') + b':' + encrypted_message
                # Send the message length first (4 bytes)
                message_length = len(message_to_send).to_bytes(4, byteorder='big')
                self.client_socket.sendall(message_length + message_to_send)
                self.display_message(f"You: {message}")  # Display the sent message in the chat
                self.entryMsg.delete(0, 'end')          # Clear the entry field
            except socket.error as e:
                # Handle socket errors during message sending
                logger.error(f"Unable to send message: {e}")
                messagebox.showerror("Send Error", f"Unable to send message: {e}")
                self.client_socket.close()
        else:
            # Warn the user if they attempt to send an empty message
            logger.warning("Empty message not sent")

    def receive_messages(self):
        """
        Listens for incoming messages from the server, decrypts them,
        and displays them in the chat interface.
        """
        while True:
            try:
                # Read the message length first (4 bytes)
                message_length_bytes = self.client_socket.recv(4)
                if not message_length_bytes:
                    break
                message_length = int.from_bytes(message_length_bytes, byteorder='big')
                data = b''
                while len(data) < message_length:
                    packet = self.client_socket.recv(message_length - len(data))
                    if not packet:
                        break
                    data += packet
                if not data:
                    break
                # The data received is in the format 'sender_client_id:encrypted_message'
                sender_client_id, encrypted_message = data.split(b':', 1)
                # Decrypt the received message
                decrypted_message = decrypt_message(self.shared_key, encrypted_message)
                if decrypted_message:
                    self.display_message(f"{sender_client_id.decode('utf-8')}: {decrypted_message}")
            except socket.error as e:
                # Handle socket errors during message reception
                logger.error(f"Unable to receive message: {e}")
                messagebox.showerror("Receive Error", f"Unable to receive message: {e}")
                break

    def display_message(self, message):
        """
        Displays a message in the conversation textbox.

        Args:
            message (str): The message to display.
        """
        self.textCons.configure(state="normal")    # Enable editing to insert the message
        self.textCons.insert("end", message + "\n")  # Insert the message at the end
        self.textCons.configure(state="disabled")  # Disable editing again
        self.textCons.yview("end")                  # Scroll to the end of the textbox

    def close_connection(self):
        """
        Handles the cleanup process when the client window is closed.
        Sends a disconnect message to the server and closes the socket connection.
        """
        logger.info(f"Client {self.client_id} is closing connection")
        try:
            if self.client_socket:
                # Notify server that client is disconnecting
                disconnect_message = f"Client {self.client_id} has left the chat."
                encrypted_message = encrypt_message(self.shared_key, disconnect_message)
                message_to_send = self.client_id.encode('utf-8') + b':' + encrypted_message
                message_length = len(message_to_send).to_bytes(4, byteorder='big')
                self.client_socket.sendall(message_length + message_to_send)
                self.client_socket.close()
        except Exception as e:
            # Log any errors that occur during disconnection
            logger.error(f"Error sending disconnect message: {e}")
        self.master.quit()


if __name__ == "__main__":
    """
    Entry point for the secure chat client application.
    Parses command-line arguments and initializes the ChatClient.
    """
    root = ctk.CTk()
    host = sys.argv[1]          # Server hostname or IP address
    server_port = sys.argv[2]   # Server port number
    client_port = sys.argv[3]   # Client port number
    client_id = sys.argv[4]     # Client identifier (e.g., "c1")
    position = (100, 100) if client_id == "c1" else (800, 100)  # Set window position based on client ID
    client = ChatClient(root, host, server_port, client_port, client_id, position)
    root.protocol("WM_DELETE_WINDOW", client.close_connection)  # Handle window close event
    root.mainloop()
