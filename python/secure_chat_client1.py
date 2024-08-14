import tkinter as tk
from tkinter import messagebox, scrolledtext, Label, Entry, Button
import socket
import threading
import logging
import sys
from cryptography.hazmat.primitives import serialization
from security.encryption import encrypt_message, decrypt_message
from security.key_management import generate_ecdh_keypair, derive_shared_key
from logging_config import setup_logging
from utils.tls_setup import configure_tls_context
import ssl

# Setup logging
logger = setup_logging()

class ChatClient:
    def __init__(self, master, host, server_port, client_port, client_id, position):
        self.master = master
        self.host = host
        self.server_port = server_port
        self.client_port = client_port
        self.client_id = client_id
        self.private_key, self.public_key = generate_ecdh_keypair()

        # Define paths to certificate and key files
        certfile = 'cert.pem'
        keyfile = 'key.pem'

        # Configure TLS context for the client
        self.tls_context = configure_tls_context(certfile, keyfile, ssl.Purpose.SERVER_AUTH)

        try:
            # Create a secure socket
            self.client_socket = self.tls_context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
            self.client_socket.bind(('0.0.0.0', int(self.client_port)))  # Bind to the specified client port
            self.client_socket.connect((self.host, int(self.server_port)))
            logger.info(f"Connected to server on port {self.server_port} from client port {self.client_port}")

            # Exchange public keys with the server (acting as a middleman)
            server_public_key_bytes = self.client_socket.recv(4096)
            self.server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
            self.client_socket.send(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Derive shared key for communication
            self.shared_key = derive_shared_key(self.private_key, server_public_key_bytes)
        except socket.error as e:
            logger.error(f"Unable to connect to server: {e}")
            messagebox.showerror("Connection Error", f"Unable to connect to server: {e}")
            self.master.quit()
            return

        self.master.title(f"Secure Chat Client {self.client_id}")
        self.master.geometry("470x550")
        self.master.configure(bg="#1a1a1a")
        self.master.geometry(f'+{position[0]}+{position[1]}')  # Set the window position

        self.create_widgets()

        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

    def create_widgets(self):
        self.labelHead = Label(self.master, bg="#1a1a1a", fg="#00FF00", text=f"Secure Chat Client {self.client_id}", font="Helvetica 14 bold", pady=5)
        self.labelHead.place(relwidth=1)

        self.line = Label(self.master, width=450, bg="#00FF00")
        self.line.place(relwidth=1, rely=0.07, relheight=0.012)

        self.textCons = scrolledtext.ScrolledText(self.master, width=20, height=2, bg="#1a1a1a", fg="#00FF00", font="Helvetica 12", padx=5, pady=5)
        self.textCons.place(relheight=0.745, relwidth=1, rely=0.08)
        self.textCons.config(state=tk.DISABLED)

        self.labelBottom = Label(self.master, bg="#1a1a1a", height=80)
        self.labelBottom.place(relwidth=1, rely=0.825)

        self.entryMsg = Entry(self.labelBottom, bg="#262626", fg="#00FF00", font="Helvetica 12")
        self.entryMsg.place(relwidth=0.74, relheight=0.06, rely=0.008, relx=0.011)
        self.entryMsg.focus()

        self.buttonMsg = Button(self.labelBottom, text="Send", font="Helvetica 12 bold", width=20, bg="#00FF00", fg="#1a1a1a", command=lambda: self.send_message())
        self.buttonMsg.place(relx=0.77, rely=0.008, relheight=0.06, relwidth=0.22)

    def send_message(self, event=None):
        message = self.entryMsg.get()
        if message.strip():
            try:
                encrypted_message = encrypt_message(self.shared_key, message)
                self.client_socket.sendall(encrypted_message.encode('utf-8'))
                self.display_message(f"You: {message}")
                self.entryMsg.delete(0, tk.END)
            except socket.error as e:
                logger.error(f"Unable to send message: {e}")
                messagebox.showerror("Send Error", f"Unable to send message: {e}")
                self.client_socket.close()
        else:
            logger.warning("Empty message not sent")

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(4096).decode('utf-8')
                if not encrypted_message:
                    break
                if "-----BEGIN PUBLIC KEY-----" in encrypted_message:
                    continue
                decrypted_message = decrypt_message(self.shared_key, encrypted_message)
                if decrypted_message:
                    self.display_message(decrypted_message)
                else:
                    logger.error("Failed to decrypt the message")
            except socket.error as e:
                logger.error(f"Unable to receive message: {e}")
                messagebox.showerror("Receive Error", f"Unable to receive message: {e}")
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                break

    def display_message(self, message):
        self.textCons.config(state=tk.NORMAL)
        self.textCons.insert(tk.END, message + "\n")
        self.textCons.config(state=tk.DISABLED)
        self.textCons.yview(tk.END)

    def close_connection(self):
        logger.info(f"Client {self.client_id} is closing connection")
        try:
            self.client_socket.sendall(encrypt_message(self.shared_key, f"Client {self.client_id} has left the chat.").encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending disconnect message: {e}")
        self.client_socket.close()
        self.master.quit()

if __name__ == "__main__":
    root = tk.Tk()
    host = sys.argv[1]
    server_port = sys.argv[2]
    client_port = sys.argv[3]
    client_id = sys.argv[4]  # Client identifier
    position = (100, 100) if client_id == "c1" else (600, 100)  # Position for client
    client = ChatClient(root, host, server_port, client_port, client_id, position)
    root.protocol("WM_DELETE_WINDOW", client.close_connection)
    root.mainloop()
