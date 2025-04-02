# main.py

import tkinter as tk
from tkinter import Label, Entry, Button, messagebox
import subprocess
import threading
import os
import sys

# Append the current directory to the system path to allow importing local modules
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from logging_config import setup_logging

def sanitize_input(input_str):
    """
    Sanitizes the input string by stripping leading/trailing whitespace
    and ensuring it contains only digits.

    Args:
        input_str (str): The input string to sanitize.

    Returns:
        str: The sanitized string if it contains only digits; otherwise, an empty string.
    """
    sanitized = input_str.strip()
    return sanitized if sanitized.isdigit() else ''

def validate_input(port_str):
    """
    Validates that the provided port string is an integer within the valid range (1024-65535).

    Args:
        port_str (str): The port number as a string.

    Returns:
        bool: True if the port is valid; False otherwise.
    """
    try:
        port = int(port_str)
        return 1024 <= port <= 65535
    except ValueError:
        return False

# Initialize the logger using the setup_logging function from logging_config
logger = setup_logging()

class ConfigWindow:
    """
    Represents the configuration window for the Secure Chat application.
    Allows users to input server and client port numbers and start the application.
    """
    def __init__(self, master):
        """
        Initializes the configuration window with labels, entry fields, and a start button.

        Args:
            master (tk.Tk): The root window.
        """
        self.master = master
        self.master.title("Secure Chat Configuration")  # Set the window title
        self.master.geometry("450x480+760+340")          # Set the window size and position
        self.master.configure(bg="#1a1a1a")             # Set the background color

        # Title label
        self.labelTitle = Label(master, text="Secure Chat Configuration",
                                font=("Courier New", 18, "bold"),
                                bg="#1a1a1a", fg="#00FF00")
        self.labelTitle.pack(pady=20)

        # Server Port label and entry
        self.labelPort = Label(master, text="Server Port:",
                               font=("Courier New", 12, "bold"),
                               bg="#1a1a1a", fg="#FFFFFF")
        self.labelPort.pack(pady=5)

        self.entryPort = Entry(master, bg="#333333", fg="#FFFFFF",
                               font=("Courier New", 12),
                               insertbackground="#FFFFFF")
        self.entryPort.pack(pady=5)
        self.entryPort.insert(0, "12345")  # Default server port

        # Client 1 Port label and entry
        self.labelClient1Port = Label(master, text="Client 1 Port:",
                                      font=("Courier New", 12, "bold"),
                                      bg="#1a1a1a", fg="#FFFFFF")
        self.labelClient1Port.pack(pady=5)

        self.entryClient1Port = Entry(master, bg="#333333", fg="#FFFFFF",
                                      font=("Courier New", 12),
                                      insertbackground="#FFFFFF")
        self.entryClient1Port.pack(pady=5)
        self.entryClient1Port.insert(0, "12346")  # Default Client 1 port

        # Client 2 Port label and entry
        self.labelClient2Port = Label(master, text="Client 2 Port:",
                                      font=("Courier New", 12, "bold"),
                                      bg="#1a1a1a", fg="#FFFFFF")
        self.labelClient2Port.pack(pady=5)

        self.entryClient2Port = Entry(master, bg="#333333", fg="#FFFFFF",
                                      font=("Courier New", 12),
                                      insertbackground="#FFFFFF")
        self.entryClient2Port.pack(pady=5)
        self.entryClient2Port.insert(0, "12347")  # Default Client 2 port

        # Start button to initiate the application
        self.buttonStart = Button(master, text="Start",
                                  font=("Courier New", 12, "bold"),
                                  bg="#00FF00", fg="#1a1a1a",
                                  command=self.start_application)
        self.buttonStart.pack(pady=20)

    def start_application(self):
        """
        Handles the logic when the Start button is clicked.
        It sanitizes and validates the input ports, and if valid,
        starts the chat application by launching server and client scripts.
        """
        logger.debug("Start button clicked")
        
        # Retrieve input values from entry fields
        server_port_input = self.entryPort.get()
        client1_port_input = self.entryClient1Port.get()
        client2_port_input = self.entryClient2Port.get()
        
        # Sanitize the input to ensure they are numeric
        server_port = sanitize_input(server_port_input)
        client1_port = sanitize_input(client1_port_input)
        client2_port = sanitize_input(client2_port_input)
        
        # Check for empty or non-numeric inputs after sanitization
        if not server_port or not client1_port or not client2_port:
            messagebox.showerror("Input Error", "All ports must be numeric and non-empty.")
            logger.error("Sanitization failed: Non-numeric or empty port values provided")
            return
        
        # Validate that each port is within the acceptable range
        invalid_ports = []
        if not validate_input(server_port):
            invalid_ports.append(f"Server Port ({server_port_input})")
        if not validate_input(client1_port):
            invalid_ports.append(f"Client 1 Port ({client1_port_input})")
        if not validate_input(client2_port):
            invalid_ports.append(f"Client 2 Port ({client2_port_input})")
        
        # If any ports are invalid, display an error message and log the issue
        if invalid_ports:
            invalid_ports_str = ', '.join(invalid_ports)
            messagebox.showerror("Input Error", f"The following ports are invalid or out of range (1024-65535): {invalid_ports_str}.")
            logger.error(f"Invalid port values provided: {invalid_ports_str}")
            return
        
        # If all validations pass, log the valid ports and start the chat application in a new thread
        logger.debug(f"Valid ports: server={server_port}, client1={client1_port}, client2={client2_port}")
        threading.Thread(target=self.run_chat_application, args=(server_port, client1_port, client2_port)).start()
        self.master.destroy()  # Close the configuration window

    def run_chat_application(self, server_port, client1_port, client2_port):
        """
        Launches the server and client scripts as separate subprocesses in new threads.

        Args:
            server_port (str): The port number for the server.
            client1_port (str): The port number for client 1.
            client2_port (str): The port number for client 2.
        """
        # Determine the base directory of the current script
        base_path = os.path.abspath(os.path.dirname(__file__))
        logger.info(f"Base path: {base_path}")

        def start_server():
            """
            Starts the server script as a subprocess.
            """
            try:
                logger.info("Starting server...")
                server_script_path = os.path.join(base_path, 'secure_chat_server.py')
                logger.info(f"Server script path: {server_script_path}")
                if not os.path.exists(server_script_path):
                    raise FileNotFoundError(f"Server script not found: {server_script_path}")
                # Launch the server script with the specified port
                subprocess.Popen(['python', server_script_path, server_port])
                logger.info("Server started successfully")
            except Exception as e:
                logger.error(f"Failed to start server: {e}")

        def start_client1():
            """
            Starts the first client script as a subprocess.
            """
            try:
                logger.info("Starting client 1...")
                client1_script_path = os.path.join(base_path, 'secure_chat_client1.py')
                logger.info(f"Client 1 script path: {client1_script_path}")
                if not os.path.exists(client1_script_path):
                    raise FileNotFoundError(f"Client 1 script not found: {client1_script_path}")
                # Launch the client 1 script with the server address and ports
                subprocess.Popen(['python', client1_script_path, 'localhost', server_port, client1_port, 'c1'])
                logger.info("Client 1 started successfully")
            except Exception as e:
                logger.error(f"Failed to start client 1: {e}")

        def start_client2():
            """
            Starts the second client script as a subprocess.
            """
            try:
                logger.info("Starting client 2...")
                client2_script_path = os.path.join(base_path, 'secure_chat_client2.py')
                logger.info(f"Client 2 script path: {client2_script_path}")
                if not os.path.exists(client2_script_path):
                    raise FileNotFoundError(f"Client 2 script not found: {client2_script_path}")
                # Launch the client 2 script with the server address and ports
                subprocess.Popen(['python', client2_script_path, 'localhost', server_port, client2_port, 'c2'])
                logger.info("Client 2 started successfully")
            except Exception as e:
                logger.error(f"Failed to start client 2: {e}")

        # Start the server and both clients in separate threads to allow concurrent execution
        threading.Thread(target=start_server).start()
        threading.Thread(target=start_client1).start()
        threading.Thread(target=start_client2).start()

if __name__ == "__main__":
    logger.debug("Starting main application")
    root = tk.Tk()                   # Initialize the main Tkinter window
    config_window = ConfigWindow(root)  # Create an instance of the ConfigWindow
    root.mainloop()                  # Start the Tkinter event loop
