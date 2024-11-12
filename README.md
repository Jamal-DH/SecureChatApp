SecureChatApp

SecureChatApp is a Python-based secure chat application designed to enable multiple clients to communicate securely over a network. The application prioritizes confidentiality, integrity, and authentication by employing advanced cryptographic techniques, including Elliptic-Curve Diffie–Hellman (ECDH) key exchange and AES-GCM encryption. Additionally, it offers features like file sharing, steganography for message concealment, and a user-friendly GUI built with CustomTkinter.

    Note: This project can be executed using the provided Python scripts as described below, or alternatively, using the Java version of the project. However, please be aware that the Java version lacks the advanced security features implemented in the Python version.

Overview

SecureChatApp is a robust and secure chat application that facilitates encrypted communication between multiple clients over a network. Leveraging state-of-the-art cryptographic methods, it ensures that messages remain confidential and tamper-proof, providing a safe environment for sensitive communications.
Features

    End-to-End Encryption: All messages between clients are encrypted using AES-GCM, ensuring both confidentiality and data integrity. Only intended recipients can decrypt and read the messages.

    AES-256 Encryption: Utilizes 256-bit AES encryption for high-level security, suitable for protecting sensitive communications.

    Secure Key Exchange (ECDH): Employs Elliptic-Curve Diffie–Hellman (ECDH) protocol for secure key exchange, creating a shared secret without exposing it to potential attackers.

    TLS Communication: Communication between the server and clients is further secured using Transport Layer Security (TLS), adding an extra layer of protection against man-in-the-middle attacks.

    Robust Key Management: Manages ECDH key pairs and shared keys securely using HKDF with SHA-256, ensuring secure handling of keys throughout the communication process.

    Secure Random Initialization Vectors (IVs): AES-GCM encryption uses cryptographically secure random IVs, ensuring that encrypting the same plaintext multiple times yields different ciphertexts, enhancing security.

    Logging: Detailed logging for monitoring encryption/decryption events, key generation, and shared key derivation. Logs are stored for troubleshooting and security analysis.

    Error Handling: Robust error handling, particularly during decryption, with detailed error messages for invalid authentication tags, decryption failures, and key management issues.

    Configurable Ports: Allows users to configure server and client ports, adding flexibility for custom network setups.

    File Sharing: Securely share files such as images and PDFs between clients, using encryption to protect file contents.

    Steganography for Message Concealment: Supports message concealment within other media, adding an extra layer of security by embedding encrypted messages within images or other files.

    Encryption & Decryption Tool: A dedicated menu tool that opens the encryption module for users to encrypt messages before sending, with easy copy-paste functionality.

    User-Friendly GUI: Built with CustomTkinter for a modern and customizable user interface, enhancing user experience.

    SSH File Transfer (Optional): Includes functionality to send files via SFTP using paramiko. Ensure that environment variables SSH_USERNAME and SSH_PASSWORD are set for SSH authentication.

    USB Authentication (Placeholder): Placeholder for USB-based authentication to enhance security during client authentication.

Getting Started

Prerequisites

    Python 3.6+: Ensure Python is installed on your machine.
    Cryptography Library: Install via pip if not already installed.

Installation

Clone the repository to your local machine:

    git clone https://github.com/Jamal-DH/SecureChatApp.git
    cd SecureChatApp

Install the required Python packages:

    pip install -r requirements.txt

Running the Application

Configure Ports

(Default values can be changed by user input):

  server_port = 12345
  client1_port = 12346
  client2_port = 12347

Start the Application

Run the main application to start the server and both clients:

     python main.py

Interact with the Chat Clients

The application launches a GUI window where you can interact with chat clients, seeing messages encrypted and decrypted in real time.

Start the application and communicate between two clients through the server. Messages sent from one client appear on the other’s screen, demonstrating end-to-end encryption.
Setup and Running the Project
Prerequisites

    Python 3.x
    OpenSSL

Setting Up the Project

Run the run.bat file or execute it from the command prompt to set up and run the project. This batch file will:

    Create a virtual environment.
    Install dependencies.
    Set necessary environment variables.
    Run the application.

Configuration Files

The tls_setup.py script generates self-signed certificates and configures the TLS context for secure communication.
Log Files

Log files are stored in the logs directory for tracking application activity and errors.
Dependencies

Install Python dependencies from requirements.txt:

    pip install -r requirements.txt

Acknowledgments

    Special thanks to the contributors of the cryptography library.
    Thanks to the developers of OpenSSL.

Author

JAMAL_ALQBAIL, AHMAD_ALBWAB , MBARAK 