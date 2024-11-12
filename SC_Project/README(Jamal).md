Title: Multi-client Server-Client Communication System

Author: JAMAL AL-DHAMSHA

Student ID: 3200606025

Field of Study: Security and Confidentiality of Networks and Information

Overview:
This Java application is designed to establish and manage a multi-client server-client communication system. The system comprises two main components: a server (S1) and two clients (C1 and C2). The application uses standard Java libraries and Swing for the graphical user interface, showcasing an implementation consistent with Java network communication practices.
Key Components:

1. Server (S1): The server manages two distinct sockets for communication with the two clients. It incorporates a thread pool to efficiently handle multiple client connections and relay messages between them. The server's graphical interface provides real-time logs of server activity, including client connections and message transfers.

2. Clients (C1 and C2): Each client has a user interface allowing users to send and receive encrypted messages. The clients connect to the server on designated ports and communicate through a secure channel using AES encryption.

3. Encryption (Enc.CryptoUtils): This utility class provides encryption and decryption functionalities using the AES algorithm, ensuring the confidentiality of messages exchanged between the clients.

Functionality:
* The server starts listening on two different ports for client connections.
* Clients C1 and C2, upon execution, connect to the server and are capable of sending and receiving encrypted messages.
* The server relays messages between the clients, maintaining a log of the communications.
* The system employs basic cryptographic techniques to secure the messages transmitted between the clients.

Usage:

1. Start the server by running the S1 class.
2. Execute C1 and C2 classes to launch the client applications.
3. Use the client interfaces to send and receive messages.

Purpose:
This application serves as a functional representation of network communication principles, particularly in the realm of secure message transmission. It demonstrates key concepts in networking such as socket programming, multi-threaded servers, and client-server architecture, along with the implementation of basic encryption for secure communication.

