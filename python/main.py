import tkinter as tk
from tkinter import Label, Entry, Button, messagebox
import subprocess
import threading
import os
import sys

# Append the current directory to the system path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from logging_config import setup_logging

# Input sanitization function
def sanitize_input(input_str):
    sanitized = input_str.strip()
    return sanitized if sanitized.isdigit() else ''

# Input validation function
def validate_input(port_str):
    try:
        port = int(port_str)
        return 1024 <= port <= 65535
    except ValueError:
        return False

# Setup logging
logger = setup_logging()

class ConfigWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Configuration")
        self.master.geometry("400x400")
        self.master.configure(bg="#1a1a1a")

        self.labelTitle = Label(master, text="Secure Chat Configuration", font=("Courier New", 18, "bold"), bg="#1a1a1a", fg="#00FF00")
        self.labelTitle.pack(pady=20)

        self.labelPort = Label(master, text="Server Port:", font=("Courier New", 12, "bold"), bg="#1a1a1a", fg="#FFFFFF")
        self.labelPort.pack(pady=5)
        self.entryPort = Entry(master, bg="#333333", fg="#FFFFFF", font=("Courier New", 12), insertbackground="#FFFFFF")
        self.entryPort.pack(pady=5)
        self.entryPort.insert(0, "12345")

        self.labelClient1Port = Label(master, text="Client 1 Port:", font=("Courier New", 12, "bold"), bg="#1a1a1a", fg="#FFFFFF")
        self.labelClient1Port.pack(pady=5)
        self.entryClient1Port = Entry(master, bg="#333333", fg="#FFFFFF", font=("Courier New", 12), insertbackground="#FFFFFF")
        self.entryClient1Port.pack(pady=5)
        self.entryClient1Port.insert(0, "12346")

        self.labelClient2Port = Label(master, text="Client 2 Port:", font=("Courier New", 12, "bold"), bg="#1a1a1a", fg="#FFFFFF")
        self.labelClient2Port.pack(pady=5)
        self.entryClient2Port = Entry(master, bg="#333333", fg="#FFFFFF", font=("Courier New", 12), insertbackground="#FFFFFF")
        self.entryClient2Port.pack(pady=5)
        self.entryClient2Port.insert(0, "12347")

        self.buttonStart = Button(master, text="Start", font=("Courier New", 12, "bold"), bg="#00FF00", fg="#1a1a1a", command=self.start_application)
        self.buttonStart.pack(pady=20)

    def start_application(self):
        logger.debug("Start button clicked")
        
        # Sanitize inputs
        server_port_input = self.entryPort.get()
        client1_port_input = self.entryClient1Port.get()
        client2_port_input = self.entryClient2Port.get()
        
        server_port = sanitize_input(server_port_input)
        client1_port = sanitize_input(client1_port_input)
        client2_port = sanitize_input(client2_port_input)
        
        # Check for empty or non-numeric inputs
        if not server_port or not client1_port or not client2_port:
            messagebox.showerror("Input Error", "All ports must be numeric and non-empty.")
            logger.error("Sanitization failed: Non-numeric or empty port values provided")
            return
        
        # Validate port ranges
        invalid_ports = []
        if not validate_input(server_port):
            invalid_ports.append(f"Server Port ({server_port_input})")
        if not validate_input(client1_port):
            invalid_ports.append(f"Client 1 Port ({client1_port_input})")
        if not validate_input(client2_port):
            invalid_ports.append(f"Client 2 Port ({client2_port_input})")
        
        if invalid_ports:
            invalid_ports_str = ', '.join(invalid_ports)
            messagebox.showerror("Input Error", f"The following ports are invalid or out of range (1024-65535): {invalid_ports_str}.")
            logger.error(f"Invalid port values provided: {invalid_ports_str}")
            return
        
        # If all validations pass, proceed to start the application
        logger.debug(f"Valid ports: server={server_port}, client1={client1_port}, client2={client2_port}")
        threading.Thread(target=self.run_chat_application, args=(server_port, client1_port, client2_port)).start()
        self.master.destroy()

    def run_chat_application(self, server_port, client1_port, client2_port):
        base_path = os.path.abspath(os.path.dirname(__file__))
        logger.info(f"Base path: {base_path}")

        def start_server():
            try:
                logger.info("Starting server...")
                server_script_path = os.path.join(base_path, 'secure_chat_server.py')
                logger.info(f"Server script path: {server_script_path}")
                if not os.path.exists(server_script_path):
                    raise FileNotFoundError(f"Server script not found: {server_script_path}")
                subprocess.Popen(['python', server_script_path, server_port])
                logger.info("Server started successfully")
            except Exception as e:
                logger.error(f"Failed to start server: {e}")

        def start_client1():
            try:
                logger.info("Starting client 1...")
                client1_script_path = os.path.join(base_path, 'secure_chat_client1.py')
                logger.info(f"Client 1 script path: {client1_script_path}")
                if not os.path.exists(client1_script_path):
                    raise FileNotFoundError(f"Client 1 script not found: {client1_script_path}")
                subprocess.Popen(['python', client1_script_path, 'localhost', server_port, client1_port, 'c1'])
                logger.info("Client 1 started successfully")
            except Exception as e:
                logger.error(f"Failed to start client 1: {e}")

        def start_client2():
            try:
                logger.info("Starting client 2...")
                client2_script_path = os.path.join(base_path, 'secure_chat_client2.py')
                logger.info(f"Client 2 script path: {client2_script_path}")
                if not os.path.exists(client2_script_path):
                    raise FileNotFoundError(f"Client 2 script not found: {client2_script_path}")
                subprocess.Popen(['python', client2_script_path, 'localhost', server_port, client2_port, 'c2'])
                logger.info("Client 2 started successfully")
            except Exception as e:
                logger.error(f"Failed to start client 2: {e}")

        threading.Thread(target=start_server).start()
        threading.Thread(target=start_client1).start()
        threading.Thread(target=start_client2).start()

if __name__ == "__main__":
    logger.debug("Starting main application")
    root = tk.Tk()
    config_window = ConfigWindow(root)
    root.mainloop()
