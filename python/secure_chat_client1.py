<<<<<<< HEAD
=======
# c1.py

>>>>>>> 730ef1f (Added updated SC_Project folder)
import os
import sys
import time
import ssl
import socket
import threading
import logging
<<<<<<< HEAD
=======
import hashlib
>>>>>>> 730ef1f (Added updated SC_Project folder)
import requests
import paramiko
import customtkinter as ctk  # Import CustomTkinter
from tkinter import messagebox, filedialog, Menu
from cryptography.hazmat.primitives import serialization
from security.encryption import encrypt_message, decrypt_message
from security.key_management import generate_ecdh_keypair, derive_shared_key
from logging_config import setup_logging
from utils.email_alert import get_system_info, format_email_body, send_email_alert
from utils.tls_setup import configure_tls_context
from file_shredder import open_shredding_menu
from messages_enc_dec import main_screen
from Steganography import SteganographyApp
from usb_auth_handle import authenticate_usb
from status_monitor import StatusMonitor, StatusWindow


# Import blockchain modules
from blockchain.blockchain_interface import BlockchainInterface

# Configuration
MAX_ATTEMPTS = 5  # Define the maximum number of authentication attempts
LOCKOUT_DURATION = 120  # Lockout duration in seconds (2 minutes)

# Setup logging
logger = setup_logging()

# Set the theme and appearance for CustomTkinter
ctk.set_appearance_mode("dark")  # Dark theme for hacker-like feel
ctk.set_default_color_theme("dark-blue")


class ChatClient:
    def __init__(self, master, host, server_port, client_port, client_id, position):
        self.master = master
        self.host = host
        self.server_port = server_port
        self.client_port = client_port
        self.client_id = client_id
        self.private_key, self.public_key = generate_ecdh_keypair()
        self.ssh_client = None
        self.client_socket = None
        self.failed_attempts = 0
        self.lockout_time = 0
<<<<<<< HEAD
=======

        # Initialize the blockchain interface
        self.blockchain = BlockchainInterface()

        # Initialize shared_key to None
        self.shared_key = None
>>>>>>> 730ef1f (Added updated SC_Project folder)

        # Fix the window size to prevent resizing
        self.master.geometry("750x230")
        self.master.title("Authentication Key")

        self.status_monitor = StatusMonitor()

        # Create the authentication UI
        self.auth_frame = ctk.CTkFrame(self.master, fg_color="#252525")
        self.auth_frame.pack(fill="both", expand=True)

        self.error_label = ctk.CTkLabel(
            self.auth_frame,
            text="ERROR: Authentication Failed",
            font=("Segoe UI", 22, "bold"),
            fg_color="#252525",
            text_color="red"
        )
        self.error_label.pack(pady=(10, 0))

        self.auth_label = ctk.CTkLabel(
            self.auth_frame,
            text="USB Not Detected or Authentication Failed. Please Insert Your USB and Click 'Try Again'.",
            font=("Segoe UI", 19),
            fg_color="#252525",
            text_color="white",
            wraplength=430
        )
        self.auth_label.pack(pady=10)

        self.try_again_button = ctk.CTkButton(
            self.auth_frame,
            text="Try Again",
            command=self.try_authenticate,
            font=("Segoe UI Bold", 13),
            fg_color="#255325",
            text_color="white"
        )
        self.try_again_button.pack(pady=20)

        self.auth_attempts_label = ctk.CTkLabel(
            self.auth_frame,
            text="",
            fg_color="#252525",
            text_color="red"
        )
        self.auth_attempts_label.pack(pady=5)

        # Perform an initial authentication attempt
        self.initial_authentication()

    def initial_authentication(self):
        try:
            if authenticate_usb():
                self.auth_frame.pack_forget()
                self.start_chat_client()
            else:
                self.auth_label.configure(
                    text="USB not detected or authentication failed. Please insert your USB and click 'Try Again'."
                )
        except Exception as e:
            messagebox.showerror("Authentication Error", f"An error occurred during initial authentication: {e}")

    def try_authenticate(self):
        # Check if lockout period is active
        if self.lockout_time > 0 and time.time() < self.lockout_time:
            remaining_time = int(self.lockout_time - time.time())
            messagebox.showwarning(
                "Authentication Locked",
                f"Too many failed attempts. Please try again in {remaining_time // 60} minutes and {remaining_time % 60} seconds."
            )
            return

        try:
            if authenticate_usb():
                self.auth_frame.pack_forget()
                self.start_chat_client()
            else:
                self.failed_attempts += 1
                remaining_attempts = max(0, MAX_ATTEMPTS - self.failed_attempts)
                self.auth_attempts_label.configure(text=f"Authentication failed. Attempts left: {remaining_attempts}")

                if remaining_attempts > 0:
                    messagebox.showerror(
                        "Authentication Failed",
                        f"Invalid USB authentication data. Attempts remaining: {remaining_attempts}."
                    )
                else:
                    # Disable the "Try Again" button when max attempts are reached
                    self.try_again_button.configure(state="disabled")

                    self.lockout_time = time.time() + LOCKOUT_DURATION
                    messagebox.showerror(
                        "Authentication Locked",
                        f"Too many failed attempts. Locked out for {LOCKOUT_DURATION // 60} minutes."
                    )

                    system_info = get_system_info()
                    subject = "USB Authentication Failed"
                    email_body, logo_data, icon_data = format_email_body(system_info, MAX_ATTEMPTS)
                    to_email = "jzororonoro@gmail.com"
                    send_email_alert(subject, email_body, to_email, logo_data)

                    self.failed_attempts = 0  # Reset the counter after locking out
        except FileNotFoundError as e:
            messagebox.showerror("USB Error", f"USB script not found: {e}")
        except Exception as e:
            messagebox.showerror("Authentication Error", f"An error occurred during authentication: {e}")

    def start_chat_client(self):
        certfile = 'cert.pem'
        keyfile = 'key.pem'

        self.tls_context = configure_tls_context(certfile, keyfile, ssl.Purpose.SERVER_AUTH)

        try:
            self.client_socket = self.tls_context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.host)
            self.client_socket.bind(('0.0.0.0', int(self.client_port)))
            self.client_socket.connect((self.host, int(self.server_port)))
            logger.info(f"Connected to server on port {self.server_port} from client port {self.client_port}")

            # Exchange public keys for ECDH
            server_public_key_bytes = self.client_socket.recv(4096)
            if not server_public_key_bytes:
                raise ValueError("Failed to receive server's public key.")
            # No need to load server's public key here since derive_shared_key handles it
            self.client_socket.send(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Derive shared key
            self.shared_key = derive_shared_key(self.private_key, server_public_key_bytes)
            if not self.shared_key:
                raise ValueError("Shared key derivation returned None.")
            logger.info(f"Derived shared key for client {self.client_id}: {self.shared_key.hex()}")

            # Update the window title and size
            self.master.title(f"Secure Chat Client {self.client_id}")
            self.master.geometry("600x680")
            self.master.configure(fg_color="#1a1a1a")
            self.master.geometry(f'+{position[0]}+{position[1]}')

            # Create UI components
            self.create_menu_bar()
            self.create_widgets()

<<<<<<< HEAD
            #self.status_Monitor = StatusWindow(alert_callback=self.handle_alert)
            #self.status_Monitor.start()

=======
            # Start a thread to receive messages
>>>>>>> 730ef1f (Added updated SC_Project folder)
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()

        except (ValueError, ssl.SSLError) as e:
            logger.error(f"Shared key derivation failed: {e}")
            messagebox.showerror("Shared Key Error", f"Shared key derivation failed: {e}")
            self.master.quit()
        except socket.error as e:
            logger.error(f"Unable to connect to server: {e}")
            messagebox.showerror("Connection Error", f"Unable to connect to server: {e}")
            self.master.quit()
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            self.master.quit()

    def check_ip_address(self):
        # Alternative Services:
<<<<<<< HEAD
        # https://api64.ipify.org?format=json 
        # https://ifconfig.me/all.json
        # https://ip-api.com/json
	# http://ipinfo.io/json
=======
        # https://api64.ipify.org?format=json
        # https://ifconfig.me/all.json
        # https://ip-api.com/json
        # http://ipinfo.io/json
>>>>>>> 730ef1f (Added updated SC_Project folder)
        try:
            response = requests.get('https://api64.ipify.org?format=json')
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            ip_info = response.json()
            public_ip = ip_info.get('ip', 'Unknown IP')
            messagebox.showinfo("IP Address", f"Current IP Address: {public_ip}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to retrieve IP Address: {e}")

    def create_menu_bar(self):
        menubar = Menu(self.master, tearoff=0)

        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Encrypt/Decrypt", command=self.open_encryption_tool)
        tools_menu.add_command(label="Send File", command=self.open_file_transfer_dialog)
        tools_menu.add_command(label="Steganography Tool", command=self.open_steganography_tool)
        tools_menu.add_command(label="Shredding", command=self.open_shredding_menu)
        tools_menu.add_command(label="Check IP Address", command=self.check_ip_address)
        tools_menu.add_separator()
        tools_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        #status_menu = Menu(menubar, tearoff=0)
        #status_menu.add_command(label="View Status", command=self.open_status_window)
        #menubar.add_cascade(label="Status", menu=status_menu)

        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about_info)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.master.config(menu=menubar)

    def show_about_info(self):
        messagebox.showinfo("About", "Advanced Secure Chat Client\nVersion 1.0\n\nDeveloped by: JAMAL_DH")

    def open_encryption_tool(self):
        main_screen()

    def open_steganography_tool(self):
        steganography_window = ctk.CTkToplevel(self.master)
        SteganographyApp(steganography_window)

    def open_shredding_menu(self):
        open_shredding_menu(self.master)

    def open_status_window(self):
        """
        Open the Status window to display real-time status information.
        """
<<<<<<< HEAD
       # self.status_monitor.start()
       # status_window = StatusWindow(self.master, self.status_monitor)
=======
        self.status_monitor.start()
        status_window = StatusWindow(self.master, self.status_monitor)
>>>>>>> 730ef1f (Added updated SC_Project folder)

    def handle_alert(self, alert):
        """
        Handle real-time alerts by displaying pop-up notifications.
        :param alert: Dictionary containing alert details.
        """
        alert_type = alert.get('type', 'Alert')
        message = alert.get('message', 'An alert has been triggered.')
        # Display alert in a pop-up message box
        messagebox.showwarning(f"{alert_type} Alert", message)

    def open_file_transfer_dialog(self):
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

            # Ensure we open a fresh SFTP session each time
            with self.ssh_client.open_sftp() as sftp:
                home_dir = sftp.normalize('.')
                remote_dir = os.path.join(home_dir, 'received_files')
                remote_path = os.path.join(remote_dir, os.path.basename(absolute_file_path))

                try:
                    sftp.chdir(remote_dir)
                    logging.info(f"Remote directory {remote_dir} exists.")
                except IOError:
                    logging.warning(f"Remote directory {remote_dir} does not exist. Attempting to create it.")
                    sftp.mkdir(remote_dir)
                    sftp.chdir(remote_dir)
                    logging.info(f"Successfully created and changed to remote directory {remote_dir}.")

                sftp.put(absolute_file_path, remote_path)
                logging.info(f"File '{absolute_file_path}' sent successfully via SFTP to '{remote_path}'.")
                self.display_message(f"File '{absolute_file_path}' sent successfully via SFTP to '{remote_path}'.")

        except FileNotFoundError as fnf_error:
            logging.error(f"File not found error: {fnf_error}")
            messagebox.showerror("File Transfer Error", f"File not found: {fnf_error}")
        except Exception as e:
            logging.error(f"Failed to send file via SFTP: {e}")
            messagebox.showerror("File Transfer Error", f"Failed to send file via SFTP: {e}")
        finally:
            # Ensure the SSH connection is closed after the transfer
            if self.ssh_client:
                self.ssh_client.close()
                self.ssh_client = None
                logging.info("SSH connection closed.")

    def setup_ssh_client(self):
        if not self.ssh_client:
            try:
                username = os.getenv('SSH_USERNAME')
                password = os.getenv('SSH_PASSWORD')

                if not username or not password:
                    raise ValueError("SSH_USERNAME and SSH_PASSWORD environment variables must be set.")

                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.load_system_host_keys()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh_client.connect(
                    self.host,
                    port=22,
                    username=username,
                    password=password
                )
                logging.info("SSH connection established.")
            except paramiko.AuthenticationException as auth_error:
                logging.error(f"Authentication failed: {auth_error}")
                messagebox.showerror("SSH Authentication Error", f"Authentication failed: {auth_error}")
            except Exception as e:
                logging.error(f"Failed to establish SSH connection: {e}")
                messagebox.showerror("SSH Connection Error", f"Failed to connect to SSH server: {e}")
                self.ssh_client = None

    def create_widgets(self):
        self.labelHead = ctk.CTkLabel(
            self.master,
            text=f"Secure Chat Client {self.client_id}",
            font=("Courier New", 20, "bold"),
            fg_color="#1a1a1a",
            text_color="#5F87AF"
        )
        self.labelHead.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        self.textbox_border_frame = ctk.CTkFrame(
            self.master,
            fg_color="#3A506B",
            corner_radius=0,
            border_width=1
        )
        self.textbox_border_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        self.textCons = ctk.CTkTextbox(
            self.textbox_border_frame,
            fg_color="#1a1a1a",
            text_color="#00FF00",
            font=("Courier New", 18),
            padx=5,
            pady=5
        )
        self.textCons.pack(fill="both", expand=True, padx=5, pady=5)
        self.textCons.configure(state="disabled")

        self.entryMsg = ctk.CTkEntry(
            self.master,
            fg_color="#262626",
            text_color="#00FF00",
            font=("Helvetica", 18)
        )
        self.entryMsg.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.entryMsg.focus()

        self.buttonMsg = ctk.CTkButton(
            self.master,
            text="Send",
            font=("Courier New", 12, "bold"),
            fg_color="#8A9BA8",
            text_color="#1a1a1a",
            command=self.send_message
        )
        self.buttonMsg.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        self.master.grid_rowconfigure(1, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=0)

    def send_message(self, event=None):
        raw_message = self.entryMsg.get()
        message = raw_message.strip()
        if message:
            try:
                # Encrypt the message
                encrypted_message = encrypt_message(self.shared_key, message)  # Returns bytes
                self.client_socket.sendall(encrypted_message)  # sendall sends all bytes
                logger.debug(f"Sent encrypted message of length {len(encrypted_message)} bytes")
                self.display_message(f"You: {message}")
                self.entryMsg.delete(0, 'end')

                # Hash the message (hex string)
                message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
                logger.info(f"Sender's computed message hash: {message_hash}")

                # Log the hash to the blockchain as a string
                tx_receipt = self.blockchain.log_message(message_hash)
                logger.info(f"Message hash logged to blockchain in transaction {tx_receipt.transactionHash.hex()}")

            except socket.error as e:
                logger.error(f"Unable to send message: {e}")
                messagebox.showerror("Send Error", f"Unable to send message: {e}")
                self.client_socket.close()
            except Exception as e:
                logger.error(f"Failed to log message hash to blockchain: {e}")
                messagebox.showerror("Blockchain Error", f"Failed to log message to blockchain: {e}")
        else:
            logger.warning("Empty message not sent")

    def receive_messages(self):
        while True:
            try:
                # Receive the encrypted message from the server
                encrypted_message = self.client_socket.recv(4096)  # bytes
                if not encrypted_message:
                    break

                # Decrypt the message
                decrypted_message = decrypt_message(self.shared_key, encrypted_message)  # returns str or None
                if decrypted_message:
                    decrypted_message = decrypted_message.strip()
                    # Compute the hash of the decrypted message
                    message_hash = hashlib.sha256(decrypted_message.encode('utf-8')).hexdigest()
                    logger.info(f"Recipient's computed message hash: {message_hash}")

                    # Verify if the message hash exists on the blockchain
                    hashes_on_chain = self.blockchain.get_past_messages()  # List of strings
                    logger.debug(f"Hashes on blockchain: {hashes_on_chain}")

                    if message_hash in hashes_on_chain:
                        verification_status = "Message verified on blockchain."
                    else:
                        verification_status = "Message not found on blockchain."

                    # Display the message with verification status
                    self.display_message(f"{decrypted_message} ({verification_status})")
                else:
                    logger.warning("Failed to decrypt received message.")
                    self.display_message("(Failed to decrypt message.)")
            except socket.error as e:
                logger.error(f"Unable to receive message: {e}")
                messagebox.showerror("Receive Error", f"Unable to receive message: {e}")
                break
            except Exception as e:
                logger.error(f"Failed to verify message hash against blockchain: {e}")
                if 'decrypted_message' in locals():
                    self.display_message(f"{decrypted_message} (Blockchain verification failed.)")
                else:
                    self.display_message(f"(Blockchain verification failed.)")

    def display_message(self, message):
        self.textCons.configure(state="normal")
        self.textCons.insert("end", message + "\n")
        self.textCons.configure(state="disabled")
        self.textCons.yview("end")

    def close_connection(self):
        logger.info(f"Client {self.client_id} is closing connection")
        try:
<<<<<<< HEAD
            if self.client_socket:
                self.client_socket.sendall(
                    encrypt_message(self.shared_key, f"Client {self.client_id} has left the chat.").encode('utf-8')
                )
=======
            if self.client_socket and hasattr(self, 'shared_key') and self.shared_key:
                # Encrypt the disconnect message
                disconnect_message = f"Client {self.client_id} has left the chat."
                encrypted_disconnect = encrypt_message(self.shared_key, disconnect_message)  # Returns bytes
                self.client_socket.sendall(encrypted_disconnect)  # Correct: send bytes directly
                self.client_socket.close()
                logger.info(f"Disconnect message sent for client {self.client_id}")
            else:
                logger.warning(f"Shared key not set for client {self.client_id}. Sending disconnect message as plain text.")
                disconnect_message = f"Client {self.client_id} has left the chat."
                self.client_socket.sendall(disconnect_message.encode('utf-8'))  # Correct: encoding string to bytes
>>>>>>> 730ef1f (Added updated SC_Project folder)
                self.client_socket.close()
        except Exception as e:
            logger.error(f"Error sending disconnect message: {e}")
        self.master.quit()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python c1.py <host> <server_port> <client_port> <client_id>")
        sys.exit(1)

    host = sys.argv[1]
    server_port = sys.argv[2]
    client_port = sys.argv[3]
    client_id = sys.argv[4]
    position = (100, 100) if client_id == "c1" else (800, 100)

    root = ctk.CTk()
    client = ChatClient(root, host, server_port, client_port, client_id, position)
    root.protocol("WM_DELETE_WINDOW", client.close_connection)
    root.mainloop()
