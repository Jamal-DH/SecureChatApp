import customtkinter as ctk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Constants
SALT_LENGTH = 16
IV_LENGTH = 16

# Set the appearance and color theme
ctk.set_appearance_mode("dark")  # Options: "dark", "light", "system"
ctk.set_default_color_theme("dark-blue")  # Options: "blue", "green", "dark-blue"

# Encryption and decryption functions using AES
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_message(plaintext, key):
    iv = os.urandom(IV_LENGTH)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV for use in decryption

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:IV_LENGTH]
    ciphertext = encrypted_message[IV_LENGTH:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def show_output_window(output_text):
    output_window = ctk.CTkToplevel()
    output_window.title("Output")
    output_window.geometry("500x400")
    output_window.configure(fg_color="#1a1a1a")

    frame = ctk.CTkFrame(output_window, fg_color="#1a1a1a")
    frame.pack(pady=10)

    ctk.CTkLabel(
        frame,
        text="Here is your output:",
        text_color="#00FF00",
        font=("Courier New", 15)
    ).pack(side="left", padx=(0, 10))

    def copy_to_clipboard():
        output_window.clipboard_clear()
        output_window.clipboard_append(output_text)
        messagebox.showinfo("Copied", "Text copied to clipboard!")

    copy_button = ctk.CTkButton(
        frame,
        text="Copy",
        font=("Courier New", 15),
        fg_color="#00FF00",
        text_color="#1a1a1a",
        command=copy_to_clipboard
    )
    copy_button.pack(side="left")

    output_textbox = ctk.CTkTextbox(
        output_window,
        font=("Courier New", 15),
        fg_color="#1a1a1a",
        text_color="#00FF00",
        wrap="word"
    )
    output_textbox.pack(pady=10, padx=10, expand=True, fill="both")

    output_textbox.insert("end", output_text)
    output_textbox.configure(state="disabled")  # Disable editing

def encrypt():
    password = code.get()
    if not password:
        messagebox.showerror("Error", "Please enter a secret key for encryption.")
        return

    text_to_encrypt = text1.get("1.0", "end").strip()
    if not text_to_encrypt:
        messagebox.showerror("Error", "Please enter text to encrypt.")
        return

    salt = os.urandom(SALT_LENGTH)
    key = generate_key(password, salt)
    encrypted_message = encrypt_message(text_to_encrypt, key)

    # Combine salt and encrypted message for storage/transport
    result = salt + encrypted_message
    show_output_window(result.hex())
    update_button_states(is_encrypted=True)

def decrypt():
    encrypted_message = text1.get("1.0", "end").strip()
    if not encrypted_message:
        messagebox.showerror("Error", "Please enter an encrypted message for decryption.")
        return

    try:
        encrypted_message = bytes.fromhex(encrypted_message)
    except ValueError:
        messagebox.showerror("Error", "Invalid encrypted message. Please enter a valid hexadecimal string.")
        return

    salt = encrypted_message[:SALT_LENGTH]
    encrypted_message = encrypted_message[SALT_LENGTH:]
    password = code.get()

    if not password:
        messagebox.showerror("Error", "Please enter a secret key for decryption.")
        return

    key = generate_key(password, salt)
    try:
        plaintext = decrypt_message(encrypted_message, key)
    except ValueError:
        messagebox.showerror("Error", "Decryption failed. Please check the secret key.")
        return

    show_output_window(plaintext)
    update_button_states(is_encrypted=False)

def reset():
    code.set("")
    text1.delete("1.0", "end")
    update_button_states(is_encrypted=False)

def check_text(event=None):
    if text1.get("1.0", "end").strip():
        encrypt_button.configure(state="normal")
        decrypt_button.configure(state="normal")
    else:
        encrypt_button.configure(state="disabled")
        decrypt_button.configure(state="disabled")

def update_button_states(is_encrypted):
    if is_encrypted:
        encrypt_button.configure(state="disabled")
        decrypt_button.configure(state="normal")
    else:
        encrypt_button.configure(state="normal")
        decrypt_button.configure(state="disabled")

def main_screen():
    screen = ctk.CTkToplevel()
    screen.geometry("520x450")
    screen.title("Encryptor")
    screen.configure(fg_color="#1a1a1a")

    # Title Label
    ctk.CTkLabel(
        screen,
        text="Enter text for encryption and decryption",
        text_color="#00FF00",
        font=("Courier New", 18)
    ).pack(pady=(10, 5))

    # Text Input
    global text1
    text1 = ctk.CTkTextbox(
        screen,
        font=("Courier New", 14),
        fg_color="#1a1a1a",
        text_color="#00FF00",
        wrap="word",
        height=100
    )
    text1.pack(pady=5, padx=10, fill="both")
    text1.bind("<KeyRelease>", check_text)

    # Secret Key Label
    ctk.CTkLabel(
        screen,
        text="Enter secret key for encryption and decryption",
        text_color="#00FF00",
        font=("Courier New", 18)
    ).pack(pady=(10, 5))

    # Secret Key Entry
    global code, encrypt_button, decrypt_button
    code = ctk.StringVar()
    entry_code = ctk.CTkEntry(
        screen,
        textvariable=code,
        font=("Courier New", 14),
        fg_color="#262626",
        text_color="#00FF00",
        show="*"
    )
    entry_code.pack(pady=5, padx=10, fill="x")

    # Buttons Frame
    buttons_frame = ctk.CTkFrame(screen, fg_color="#1a1a1a")
    buttons_frame.pack(pady=10)

    encrypt_button = ctk.CTkButton(
        buttons_frame,
        text="ENCRYPT",
        font=("Courier New", 14),
        fg_color="#3A506B",
        text_color="#1a1a1a",
        command=encrypt,
        width=100
    )
    encrypt_button.pack(side="left", padx=5)
    encrypt_button.configure(state="normal")

    decrypt_button = ctk.CTkButton(
        buttons_frame,
        text="DECRYPT",
        font=("Courier New", 14),
        fg_color="#3A506B",
        text_color="#1a1a1a",
        command=decrypt,
        width=100
    )
    decrypt_button.pack(side="left", padx=5)
    decrypt_button.configure(state="normal")

    reset_button = ctk.CTkButton(
        buttons_frame,
        text="RESET",
        font=("Courier New", 14),
        fg_color="#350606",
        text_color="#1a1a1a",
        command=reset,
        width=100
    )
    reset_button.pack(side="left", padx=5)

    screen.focus()

# Uncomment the following lines to run the application independently
# if __name__ == "__main__":
#     root = ctk.CTk()
#     main_screen()
#     root.mainloop()
