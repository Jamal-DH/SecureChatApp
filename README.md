SecureChatApp

Note: This project can be executed using the provided Python scripts as described below, or alternatively, using the Java version of the project. However, please be aware that the Java version lacks the advanced security features implemented in the Python version.

Overview

SecureChatApp is a Python-based secure chat application designed to enable multiple clients to communicate securely over a network. The application prioritizes confidentiality, integrity, and authentication by employing advanced cryptographic techniques, including Elliptic-curve Diffie–Hellman (ECDH) key exchange and AES-GCM encryption.


Features: 


End-to-End Encryption: All messages between clients are encrypted using AES-GCM, a robust encryption mode that provides both confidentiality and data integrity. This ensures that only the intended recipients can decrypt and read the messages, with the integrity of the message verified automatically.


AES-256 Encryption: The application uses AES encryption with a 256-bit key length, offering a high level of security suitable for protecting sensitive communications.


Secure Key Exchange: SecureChatApp utilizes the Elliptic-curve Diffie–Hellman (ECDH) protocol for secure key exchange. This method allows the creation of a shared secret between two parties over an insecure channel, without exposing the shared key to potential attackers.


TLS Communication: The communication between the server and clients is further secured using Transport Layer Security (TLS). This adds an additional layer of protection against man-in-the-middle attacks by ensuring that the data transmitted over the network is encrypted and secure.


Robust Key Management: The application includes a comprehensive key management system, which involves generating ECDH key pairs, deriving shared keys using the HKDF function with SHA-256, and securely managing keys throughout the communication process.


Secure Random Initialization Vectors (IVs): AES-GCM encryption in SecureChatApp employs cryptographically secure random Initialization Vectors (IVs) generated using os.urandom(). This ensures that the same plaintext encrypted multiple times will yield different ciphertexts, enhancing security.


Logging: Detailed logging is implemented throughout the application to monitor activities, including successful and failed encryption/decryption events, key generation, and shared key derivation. This logging is crucial for troubleshooting and maintaining a secure environment.


Error Handling: The application includes robust error handling mechanisms, particularly during the decryption process. It logs detailed error messages for issues such as invalid authentication tags, general decryption failures, and key management errors, ensuring that potential security issues are identified and addressed.


Configurable Ports: Users have the ability to configure server and client ports before initiating the chat. This flexibility allows for custom network setups and can help in avoiding port conflicts with other applications.




Getting Started

Prerequisites

    Python 3.6+: Make sure you have Python installed on your machine.
    Cryptography Library: The application depends on the cryptography library, which can be installed via pip.

#Installation

Clone the repository to your local machine:

     git clone https://github.com/Jamal-DH/SecureChatApp.git
     cd SecureChatApp



#Install the required Python packages:



    pip install -r requirements.txt

#Running the Application

   Configure Ports (default values can be changed by user input):
        
    server_port = 12345
    client1_port = 12346
    client2_port = 12347

Start the Application:

    #Run the main application to start the server and both clients:

        python main.py

Interact with the Chat Clients:
   The application will launch a GUI window where you can interact with the chat clients. Type messages and see them encrypted and decrypted in real-time.

Detailed Functionality
Key Management (key_management.py)

    generate_ecdh_keypair(): Generates a public-private key pair using ECDH on the SECP384R1 curve.
    derive_shared_key(private_key, peer_public_key_bytes): Derives a shared secret using ECDH and applies HKDF to create a 256-bit shared key.

Encryption (encryption.py)

    encrypt_message(key, plaintext): Encrypts a plaintext message using AES-GCM, producing a base64 encoded string.
    decrypt_message(key, encrypted_message): Decrypts an AES-GCM encrypted message, returning the original plaintext.

Server (secure_chat_server.py)

    The server listens for incoming client connections, manages key exchanges, and facilitates secure message broadcasting among clients.

Clients (secure_chat_client1.py, secure_chat_client2.py)

    Each client connects to the server, performs key exchange, and allows users to send and receive encrypted messages via a simple GUI.

Logging (logging_config.py, test_logging.py)

    Configures and tests logging, with logs written to both the console and a rotating log file (secure_chat.log).

Input Validation (validation.py)

    Validates user input to ensure only safe and expected data is processed by the application.

Example Usage

    Start the application and interact with two clients communicating through the server. Messages sent by one client will appear on the other client's window, demonstrating end-to-end encryption.

Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.



## Project Structure

The project directory contains the following structure:

│   .gitattributes
│   .gitignore
│   cert.pem
│   fix.bat
│   key.pem
│   README.md
│   run.bat
│   selfsigned.crt
│   selfsigned.key
│
├───.venv
│
├───python
│   │   cert.pem
│   │   config.py # Configuration file for server and client ports
│   │   key.pem
│   │   logging_config.py	# Configuration for logging setup
│   │   main.py		# Main entry point for the application
│   │   requirements.txt  	# Python dependencies
│   │   secure_chat_client1.py
│   │   secure_chat_client2.py
│   │   secure_chat_server.py
│   │   selfsigned.crt
│   │   selfsigned.key
│   │   test_logging.py
│   │   validation.py		# Module for validating user input
│   │   __init__.py
│   │
│   ├───logs
│   │       secure_chat.log
│   │
│   ├───security
│   │   │   encryption.py	# Module for encrypting and decrypting messages
│   │   │   key_management.py	# Module for ECDH key generation and shared key derivation
│   │   │   __init__.py
│   │   │
│   │   └───__pycache__
│   │           encryption.cpython-312.pyc
│   │           key_management.cpython-312.pyc
│   │           __init__.cpython-312.pyc
│   │
│   ├───utils
│   │   │   input_sanitization.py
│   │   │   tls_setup.py
│   │   │   __init__.py
│   │   │
│   │   └───__pycache__
│   │           input_sanitization.cpython-312.pyc
│   │           tls_setup.cpython-312.pyc
│   │           __init__.cpython-312.pyc
│   │
│   └───__pycache__
│           logging_config.cpython-312.pyc
│           main.cpython-312.pyc
│           validation.cpython-312.pyc
│           __init__.cpython-312.pyc
│
├───SC_Project
│   │   build.xml
│   │   manifest.mf
│   │   README(Jamal).txt
│   │
│   ├───build
│   │   │   built-jar.properties
│   │   │
│   │   ├───classes
│   │   │   │   .netbeans_automatic_build
│   │   │   │   .netbeans_update_resources
│   │   │   │
│   │   │   ├───C1
│   │   │   │       C1.class
│   │   │   │
│   │   │   ├───C2
│   │   │   │       C2.class
│   │   │   │
│   │   │   ├───Enc
│   │   │   │       CryptoUtils.class
│   │   │   │
│   │   │   ├───passwordutil
│   │   │   │       PasswordUtil.class
│   │   │   │
│   │   │   ├───S1
│   │   │   │       S1$1.class
│   │   │   │       S1$ClientHandler.class
│   │   │   │       S1$PasswordPanel$1.class
│   │   │   │       S1$PasswordPanel.class
│   │   │   │       S1.class
│   │   │   │
│   │   │   ├───sc_project
│   │   │   │       SC_Project.class
│   │   │   │
│   │   │   ├───SecureC1
│   │   │   └───SecureC2
│   │   │           SecureC2.class
│   │   │
│   │   ├───empty
│   │   └───generated-sources
│   │       └───ap-source-output
│   ├───dist
│   │   │   README.TXT
│   │   │   SC_Project.jar
│   │   │
│   │   └───lib
│   │           jbcrypt-0.4.jar
│   │
│   ├───nbproject
│   │   │   build-impl.xml
│   │   │   genfiles.properties
│   │   │   project.properties
│   │   │   project.xml
│   │   │
│   │   └───private
│   │           config.properties
│   │           private.properties
│   │           private.xml
│   │
│   ├───src
│   │   ├───C1
│   │   │       C1.java
│   │   │
│   │   ├───C2
│   │   │       C2.java
│   │   │
│   │   ├───Enc
│   │   │       CryptoUtils.java
│   │   │
│   │   ├───passwordutil
│   │   │       PasswordUtil.java
│   │   │
│   │   ├───S1
│   │   │       S1.java
│   │   │
│   │   ├───sc_project
│   │   │       SC_Project.java
│   │   │
│   │   ├───SecureC1
│   │   │       SecureC1.java
│   │   │
│   │   └───SecureC2
│   │           SecureC2.java
│   │
│   └───test
└───ssl
    └───OpenSSL-Win64


## Setup and Running the Project

### Prerequisites

- Python 3.x
- OpenSSL

### Setting Up the Project



Run the Batch File:

Double-click the run.bat file or run it from the command prompt to set up and run the project.
The batch file will create a virtual environment, install the required dependencies, set the necessary environment variables, and run the application.
Configuration Files
The tls_setup.py script is responsible for generating self-signed certificates and configuring the TLS context for secure communication.

Log Files: 

Log files are generated and stored in the logs directory to keep track of the application's activities and errors.

Dependencies
The requirements.txt file contains the Python dependencies required for the project:

        cryptography   

Acknowledgements
Thanks to the contributors of the cryptography library.
Thanks to the developers of OpenSSL.

Author : JAMAL_ALQBAIL