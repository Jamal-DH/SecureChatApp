import tkinter as tk
from tkinter import messagebox, filedialog, Menu, Label, Entry, Button, scrolledtext
import os
import logging
import importlib.util
import time

# Configuration for USB Authentication
USB_MOUNT_PATH = "E:\\usb_auth.py"  # This path points to USB script
MAX_ATTEMPTS = 5  # Maximum number of attempts before lockout
LOCKOUT_DURATION = 600  # Lockout duration in seconds (10 minutes)

# Tracks the number of failed attempts and lockout status
failed_attempts = 0
lockout_time = 0

def load_usb_auth_data():
    """
    Dynamically loads and returns the hashed authentication data from the usb_auth.py script on the USB.
    Improved to handle errors and provide more informative messages.
    """
    try:
        if not os.path.exists(USB_MOUNT_PATH):
            print(f"USB script not found at {USB_MOUNT_PATH}. Ensure the path is correct and the USB is inserted.")
            return None
        
        spec = importlib.util.spec_from_file_location("usb_auth", USB_MOUNT_PATH)
        usb_auth = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(usb_auth)
        return usb_auth.get_hashed_data()
    except Exception as e:
        print(f"Error loading USB auth data: {e}")
        return None

def authenticate_usb():
    """
    Authenticates the user by checking for the correct USB with the authentication data.
    Returns True if successful, False otherwise.
    """
    global failed_attempts, lockout_time

    if lockout_time > 0 and time.time() < lockout_time:
        remaining_time = int((lockout_time - time.time()) / 60)
        print(f"Authentication locked. Try again in {remaining_time} minutes.")
        return False

    usb_hashed_data = load_usb_auth_data()

    if usb_hashed_data is None:
        print("Error loading USB auth data. Please check the USB mount path and script.")
        return False

    # Load expected hash directly from usb_auth.py
    expected_hash = usb_hashed_data

    if usb_hashed_data == expected_hash:
        print("Authentication successful.")
        failed_attempts = 0  # Reset attempts on success
        return True
    else:
        failed_attempts += 1
        print(f"Authentication failed. Incorrect data. Remaining attempts: {MAX_ATTEMPTS - failed_attempts}")

        if failed_attempts >= MAX_ATTEMPTS:
            lockout_time = time.time() + LOCKOUT_DURATION
            print(f"Too many failed attempts. Locked out for {LOCKOUT_DURATION / 60} minutes.")
            failed_attempts = 0  # Reset the counter after locking out
        return False