from tkinter import *
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Constants
SALT_LENGTH = 16
IV_LENGTH = 16

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
    output_window = Toplevel()
    output_window.title("Output")
    output_window.geometry("400x200")

    frame = Frame(output_window)
    frame.pack(pady=5)

    Label(frame, text="Here is your output:", font=("Segoe UI", 13)).pack(side=LEFT, padx=(0, 10))

    def copy_to_clipboard():
        output_window.clipboard_clear()
        output_window.clipboard_append(output_text)
        messagebox.showinfo("Copied", "Text copied to clipboard!")

    copy_button = Button(frame, text="Copy",  bd=0, bg="#0D47A1", fg="white", height="1", width=6, command=copy_to_clipboard)
    copy_button.pack(side=LEFT)

    output_textbox = Text(output_window, font="Robote 12", bg="white", wrap=WORD, bd=0)
    output_textbox.pack(pady=10, padx=10, expand=True, fill=BOTH)

    output_textbox.insert(END, output_text)
    output_textbox.config(state=DISABLED)  # Disable editing
    output_textbox.bind("<Control-c>", lambda e: None)  # Allow copying
    output_textbox.bind("<Control-C>", lambda e: None)  # Allow copying

def encrypt():
    password = code.get()
    if not password:
        messagebox.showerror("Error", "Please enter a secret key for encryption.")
        return

    text_to_encrypt = text1.get("1.0", END).strip()
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
    encrypted_message = text1.get("1.0", END).strip()
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
    text1.delete("1.0", END)
    update_button_states(is_encrypted=False)

def check_text():
    if text1.get("1.0", END).strip():
        encrypt_button.config(state="normal")
        decrypt_button.config(state="normal")
    else:
        encrypt_button.config(state="disabled")
        decrypt_button.config(state="disabled")

def update_button_states(is_encrypted):
    if is_encrypted:
        encrypt_button.config(state="disabled")
        decrypt_button.config(state="normal")
    else:
        encrypt_button.config(state="normal")
        decrypt_button.config(state="disabled")

def main_screen():
   
    screen = Toplevel()
    screen.geometry("375x398")
    screen.title("ENCRYPTOR")

    Label(screen, text="Enter text for encryption and decryption", fg="black", font=("Segoe UI", 13)).place(x=10, y=10)

    global text1
    text1 = Text(screen, font="Robote 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, height=100, width=355)
    text1.bind("<KeyRelease>", lambda event: check_text())

    Label(screen, text="Enter secret key for encryption and decryption", fg="black", font=("Segoe UI", 13)).place(x=10, y=170)

    global code, encrypt_button, decrypt_button
    code = StringVar()
    Entry(screen, textvariable=code, font="Robote 20", bg="white", width=19, bd=0, show="*").place(x=10, y=200, height=48, width=355)

    encrypt_button = Button(screen, text="ENCRYPT", bd=0, bg="#0D47A1", fg="white", height="2", width=23, command=encrypt)
    encrypt_button.place(x=10, y=250)
    encrypt_button.config(state="normal")

    decrypt_button = Button(screen, text="DECRYPT", bd=0, bg="#0D47A1", fg="white", height="2", width=23, command=decrypt)
    decrypt_button.place(x=200, y=250)
    decrypt_button.config(state="normal")

    Button(screen, text="RESET", bd=0, bg="#00bd56", fg="white", height="2", width=50, command=reset).place(x=10, y=300)

    
    screen.focus()
