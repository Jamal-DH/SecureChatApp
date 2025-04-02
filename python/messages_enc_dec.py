# message_enc_dec.py

import customtkinter as ctk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Constants for salt and initialization vector (IV) lengths
SALT_LENGTH = 16
IV_LENGTH = 16

# Configure the appearance mode and color theme for CustomTkinter
ctk.set_appearance_mode("dark")  # Options: "dark", "light", "system"
ctk.set_default_color_theme("dark-blue")  # Options: "blue", "green", "dark-blue"

def generate_key(password, salt):
    """
    Generates a cryptographic key from a password and salt using PBKDF2 HMAC with SHA256.

    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt to use in key derivation.

    Returns:
        bytes: The derived cryptographic key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,              # Length of the derived key in bytes
        salt=salt,              # Salt for key derivation
        iterations=100000,      # Number of iterations for the KDF
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key from the password
    return key

def encrypt_message(plaintext, key):
    """
    Encrypts a plaintext message using AES encryption in CFB mode.

    Args:
        plaintext (str): The message to encrypt.
        key (bytes): The encryption key.

    Returns:
        bytes: The IV concatenated with the ciphertext.
    """
    iv = os.urandom(IV_LENGTH)  # Generate a random Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # Create AES cipher
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()  # Encrypt the plaintext
    return iv + ciphertext  # Prepend IV for use in decryption

def decrypt_message(encrypted_message, key):
    """
    Decrypts an encrypted message using AES decryption in CFB mode.

    Args:
        encrypted_message (bytes): The IV concatenated with the ciphertext.
        key (bytes): The decryption key.

    Returns:
        str: The decrypted plaintext message.
    """
    iv = encrypted_message[:IV_LENGTH]  # Extract the IV from the beginning
    ciphertext = encrypted_message[IV_LENGTH:]  # Extract the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # Create AES cipher
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext
    return plaintext.decode()  # Decode bytes to string

def show_output_window(output_text):
    """
    Displays the output text in a new window with options to copy the text.

    Args:
        output_text (str): The text to display in the output window.
    """
    output_window = ctk.CTkToplevel()  # Create a new top-level window
    output_window.title("Output")  # Set the window title
    output_window.attributes("-topmost", True)  # Keep the window on top
    output_window.lift()  # Bring the window to the front
    output_window.geometry("500x400")  # Set the window size
    output_window.configure(fg_color="#1a1a1a")  # Set the background color

    frame = ctk.CTkFrame(output_window, fg_color="#1a1a1a")  # Create a frame to hold widgets
    frame.pack(pady=10)

    # Label indicating the output section
    ctk.CTkLabel(
        frame,
        text="Here is your output:",
        text_color="#00FF00",
        font=("Courier New", 15)
    ).pack(side="left", padx=(0, 10))

    def copy_to_clipboard():
        """
        Copies the output text to the system clipboard and shows a confirmation message.
        """
        output_window.clipboard_clear()  # Clear the clipboard
        output_window.clipboard_append(output_text)  # Append the output text to the clipboard
        messagebox.showinfo("Copied", "Text copied to clipboard!")  # Show confirmation

    # Button to copy the output text to the clipboard
    copy_button = ctk.CTkButton(
        frame,
        text="Copy",
        font=("Courier New", 15),
        fg_color="#00FF00",
        text_color="#1a1a1a",
        command=copy_to_clipboard
    )
    copy_button.pack(side="left")

    # Textbox to display the output text
    output_textbox = ctk.CTkTextbox(
        output_window,
        font=("Courier New", 15),
        fg_color="#1a1a1a",
        text_color="#00FF00",
        wrap="word"
    )
    output_textbox.pack(pady=10, padx=10, expand=True, fill="both")

    output_textbox.insert("end", output_text)  # Insert the output text
    output_textbox.configure(state="disabled")  # Disable editing of the textbox

def encrypt():
    """
    Handles the encryption process when the Encrypt button is clicked.
    Validates input, encrypts the message, and displays the encrypted output.
    """
    password = code.get()  # Retrieve the secret key from the entry field
    if not password:
        messagebox.showerror("Error", "Please enter a secret key for encryption.")  # Show error if key is missing
        return

    text_to_encrypt = text1.get("1.0", "end").strip()  # Get the text to encrypt from the textbox
    if not text_to_encrypt:
        messagebox.showerror("Error", "Please enter text to encrypt.")  # Show error if text is missing
        return

    salt = os.urandom(SALT_LENGTH)  # Generate a random salt
    key = generate_key(password, salt)  # Derive the encryption key
    encrypted_message = encrypt_message(text_to_encrypt, key)  # Encrypt the message

    # Combine salt and encrypted message for storage or transport
    result = salt + encrypted_message
    show_output_window(result.hex())  # Display the encrypted message in hexadecimal format
    update_button_states(is_encrypted=True)  # Update button states based on encryption

def decrypt():
    """
    Handles the decryption process when the Decrypt button is clicked.
    Validates input, decrypts the message, and displays the decrypted output.
    """
    encrypted_message = text1.get("1.0", "end").strip()  # Get the encrypted message from the textbox
    if not encrypted_message:
        messagebox.showerror("Error", "Please enter an encrypted message for decryption.")  # Show error if input is missing
        return

    try:
        encrypted_message = bytes.fromhex(encrypted_message)  # Convert hexadecimal string to bytes
    except ValueError:
        messagebox.showerror("Error", "Invalid encrypted message. Please enter a valid hexadecimal string.")  # Show error for invalid format
        return

    salt = encrypted_message[:SALT_LENGTH]  # Extract the salt from the encrypted message
    encrypted_message = encrypted_message[SALT_LENGTH:]  # Extract the ciphertext
    password = code.get()  # Retrieve the secret key from the entry field

    if not password:
        messagebox.showerror("Error", "Please enter a secret key for decryption.")  # Show error if key is missing
        return

    key = generate_key(password, salt)  # Derive the decryption key
    try:
        plaintext = decrypt_message(encrypted_message, key)  # Decrypt the message
    except ValueError:
        messagebox.showerror("Error", "Decryption failed. Please check the secret key.")  # Show error if decryption fails
        return

    show_output_window(plaintext)  # Display the decrypted message
    update_button_states(is_encrypted=False)  # Update button states based on decryption

def reset():
    """
    Resets the input fields and button states to their default values.
    """
    code.set("")  # Clear the secret key entry field
    text1.delete("1.0", "end")  # Clear the textbox
    update_button_states(is_encrypted=False)  # Reset button states

def check_text(event=None):
    """
    Checks if there is any text in the textbox and enables or disables buttons accordingly.

    Args:
        event: The event that triggered this function (optional).
    """
    if text1.get("1.0", "end").strip():
        encrypt_button.configure(state="normal")  # Enable Encrypt and Decrypt buttons if text is present
        decrypt_button.configure(state="normal")
    else:
        encrypt_button.configure(state="disabled")  # Disable Encrypt and Decrypt buttons if textbox is empty
        decrypt_button.configure(state="disabled")

def update_button_states(is_encrypted):
    """
    Updates the state of the Encrypt and Decrypt buttons based on encryption status.

    Args:
        is_encrypted (bool): Indicates whether the current state is after encryption.
    """
    if is_encrypted:
        encrypt_button.configure(state="disabled")  # Disable Encrypt button after encryption
        decrypt_button.configure(state="normal")     # Enable Decrypt button
    else:
        encrypt_button.configure(state="normal")     # Enable Encrypt button
        decrypt_button.configure(state="disabled")   # Disable Decrypt button

def main_screen():
    """
    Creates and displays the main GUI window for the encryption and decryption application.
    """
    screen = ctk.CTkToplevel()  # Create a new top-level window
    screen.attributes("-topmost", False)  # Keep the window on top 
    screen.geometry("520x450")  # Set the window size
    screen.title("Encryptor")    # Set the window title
    screen.configure(fg_color="#1a1a1a")  # Set the background color

    # Title Label
    ctk.CTkLabel(
        screen,
        text="Enter text for encryption and decryption",
        text_color="#00FF00",
        font=("Courier New", 18)
    ).pack(pady=(10, 5))  # Add padding above and below the label

    # Text Input Box for Encryption/Decryption
    global text1
    text1 = ctk.CTkTextbox(
        screen,
        font=("Courier New", 14),
        fg_color="#1a1a1a",
        text_color="#00FF00",
        wrap="word",
        height=100
    )
    text1.pack(pady=5, padx=10, fill="both")  # Pack the textbox with padding and fill
    text1.bind("<KeyRelease>", check_text)  # Bind key release event to check_text function

    # Secret Key Label
    ctk.CTkLabel(
        screen,
        text="Enter secret key for encryption and decryption",
        text_color="#00FF00",
        font=("Courier New", 18)
    ).pack(pady=(10, 5))  # Add padding above and below the label

    # Secret Key Entry Field
    global code, encrypt_button, decrypt_button
    code = ctk.StringVar()  # Variable to hold the secret key
    entry_code = ctk.CTkEntry(
        screen,
        textvariable=code,
        font=("Courier New", 14),
        fg_color="#262626",
        text_color="#00FF00",
        show="*"  # Mask the input with asterisks
    )
    entry_code.pack(pady=5, padx=10, fill="x")  # Pack the entry field with padding and fill

    # Frame to hold the buttons
    buttons_frame = ctk.CTkFrame(screen, fg_color="#1a1a1a")
    buttons_frame.pack(pady=10)

    # Encrypt Button
    encrypt_button = ctk.CTkButton(
        buttons_frame,
        text="ENCRYPT",
        font=("Courier New", 14),
        fg_color="#3A506B",
        text_color="#1a1a1a",
        command=encrypt,
        width=100
    )
    encrypt_button.pack(side="left", padx=5)  # Pack the button to the left with padding
    encrypt_button.configure(state="normal")  # Set the initial state to normal

    # Decrypt Button
    decrypt_button = ctk.CTkButton(
        buttons_frame,
        text="DECRYPT",
        font=("Courier New", 14),
        fg_color="#3A506B",
        text_color="#1a1a1a",
        command=decrypt,
        width=100
    )
    decrypt_button.pack(side="left", padx=5)  # Pack the button to the left with padding
    decrypt_button.configure(state="normal")  # Set the initial state to normal

    # Reset Button
    reset_button = ctk.CTkButton(
        buttons_frame,
        text="RESET",
        font=("Courier New", 14),
        fg_color="#350606",
        text_color="#1a1a1a",
        command=reset,
        width=100
    )
    reset_button.pack(side="left", padx=5)  # Pack the button to the left with padding

    screen.focus()  # Set focus to the main screen

# Uncomment the following lines to run the application independently
# if __name__ == "__main__":
#     root = ctk.CTk()
#     main_screen()
#     root.mainloop()
