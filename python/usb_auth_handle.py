# usb_auth_handle.py

import os
import hashlib
import json
import time
import logging
import importlib.util
from tkinter import messagebox, Tk
import win32api  # Requires PyWin32 for Windows API interactions

# -------------------- Configuration --------------------

# Configuration for USB Authentication
USB_VOLUME_LABEL = "TESTER"  # Replace with your USB's volume label
USB_SCRIPT_NAME = "usb_auth.py"  # The authentication script expected on the USB
EXPECTED_HASH = "c2396e47a3f4b3df4e1be9ae3c400876f804ac5dedd1b46e83477e92fad4487f"  # Expected hash of the authentication data
EXPECTED_CHECKSUM = "cdebf4c15a3a41c46173d8c14d2f4529338ae67cd31646d4d5e53ffd8b674140"  # Expected checksum of usb_auth.py

MAX_ATTEMPTS = 5          # Maximum number of authentication attempts allowed before lockout
LOCKOUT_DURATION = 600    # Lockout duration in seconds (10 minutes) after exceeding max attempts
AUTH_STATE_FILE = "auth_state.json"  # File to store authentication state (failed attempts and lockout time)
LOG_FILE = "auth.log"     # Log file to record authentication events and errors

# -------------------- Setup Logging --------------------

logging.basicConfig(
    filename=LOG_FILE,           # Log messages will be written to 'auth.log'
    level=logging.INFO,          # Log level set to INFO; can be adjusted as needed
    format='%(asctime)s - %(levelname)s - %(message)s'  # Log message format
)

# -------------------- Authentication State Management --------------------

def load_auth_state():
    """
    Loads the authentication state from a JSON file.
    If the file does not exist or fails to load, returns a default state.
    
    Returns:
        dict: A dictionary containing 'failed_attempts' and 'lockout_time'.
    """
    if os.path.exists(AUTH_STATE_FILE):
        try:
            with open(AUTH_STATE_FILE, 'r') as f:
                state = json.load(f)
                return state
        except Exception as e:
            logging.error(f"Failed to load auth state: {e}")
    # Default state if file does not exist or fails to load
    return {"failed_attempts": 0, "lockout_time": 0}

def save_auth_state(state):
    """
    Saves the authentication state to a JSON file.
    
    Args:
        state (dict): The authentication state to save.
    """
    try:
        with open(AUTH_STATE_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        logging.error(f"Failed to save auth state: {e}")

# -------------------- USB Detection --------------------

def find_usb_path():
    """
    Searches for the USB drive based on the configured volume label.
    If found, returns the full path to the expected authentication script.
    
    Returns:
        str or None: The full path to 'usb_auth.py' on the USB if found, else None.
    """
    try:
        # Retrieve all logical drive strings (e.g., ['A:\\', 'C:\\', 'D:\\', ...])
        drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
        for drive in drives:
            try:
                vol_info = win32api.GetVolumeInformation(drive)
                volume_label = vol_info[0]
                if volume_label == USB_VOLUME_LABEL:
                    usb_path = os.path.join(drive, USB_SCRIPT_NAME)
                    if os.path.exists(usb_path):
                        return usb_path  # USB with the correct volume label and authentication script found
            except Exception:
                continue  # Skip drives that cause errors (e.g., inaccessible drives)
    except Exception as e:
        logging.error(f"Error detecting USB drives: {e}")
    return None  # USB not found

# -------------------- Integrity Verification --------------------

def compute_file_checksum(file_path):
    """
    Computes the SHA-256 checksum of a given file.
    
    Args:
        file_path (str): The path to the file for which to compute the checksum.
    
    Returns:
        str or None: The hexadecimal checksum string if successful, else None.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Failed to compute checksum for {file_path}: {e}")
        return None

# -------------------- Load USB Auth Data --------------------

def load_usb_auth_data(usb_path):
    """
    Loads and returns the hashed authentication data from 'usb_auth.py' on the USB.
    Verifies the integrity of 'usb_auth.py' before loading.
    
    Args:
        usb_path (str): The full path to 'usb_auth.py' on the USB.
    
    Returns:
        str or None: The hashed authentication data if successful, else None.
    """
    try:
        # Verify the integrity of usb_auth.py by comparing its checksum
        actual_checksum = compute_file_checksum(usb_path)
        if actual_checksum != EXPECTED_CHECKSUM:
            logging.warning("usb_auth.py checksum mismatch. Possible tampering detected.")
            messagebox.showerror("Authentication Error", "USB authentication script integrity check failed.")
            return None

        # Dynamically import usb_auth.py to retrieve authentication data
        spec = importlib.util.spec_from_file_location("usb_auth", usb_path)
        usb_auth = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(usb_auth)

        # Retrieve hashed authentication data from usb_auth.py
        usb_hashed_data = usb_auth.get_hashed_data()

        return usb_hashed_data

    except Exception as e:
        logging.error(f"Error loading USB auth data: {e}")
        messagebox.showerror("Authentication Error", "Failed to load USB authentication data.")
        return None

# -------------------- Authenticate USB --------------------

def authenticate_usb():
    """
    Authenticates the user by verifying the USB's hashed data.
    Implements attempt tracking and lockout mechanisms.
    
    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    # Initialize Tkinter root (hidden) for displaying message boxes
    root = Tk()
    root.withdraw()  # Hide the main window

    state = load_auth_state()  # Load current authentication state
    current_time = time.time()  # Get the current timestamp

    # Check if the user is currently locked out due to too many failed attempts
    if state["lockout_time"] > current_time:
        remaining_time = int(state["lockout_time"] - current_time)
        minutes, seconds = divmod(remaining_time, 60)
        messagebox.showwarning(
            "Authentication Locked",
            f"Too many failed attempts. Please try again in {minutes} minutes and {seconds} seconds."
        )
        root.destroy()
        return False

    usb_path = find_usb_path()  # Attempt to find the USB drive

    if not usb_path:
        # Display error if USB is not found
        messagebox.showerror(
            "USB Not Found",
            f"USB not found. Please insert the correct USB and try again."
        )
        logging.warning("USB drive not found.")
        root.destroy()
        return False

    usb_hashed_data = load_usb_auth_data(usb_path)  # Load and verify USB authentication data

    if usb_hashed_data is None:
        # Error message already displayed in load_usb_auth_data
        root.destroy()
        return False

    # Compare the loaded hashed data with the expected hash
    if usb_hashed_data == EXPECTED_HASH:
        logging.info("Authentication successful.")
        state["failed_attempts"] = 0      # Reset failed attempts on successful authentication
        state["lockout_time"] = 0         # Clear any lockout
        save_auth_state(state)            # Save the updated state
        messagebox.showinfo("Authentication Successful", "USB authentication successful.")
        root.destroy()
        return True
    else:
        # Handle failed authentication attempt
        state["failed_attempts"] += 1
        remaining_attempts = MAX_ATTEMPTS - state["failed_attempts"]
        logging.warning(f"Authentication failed. Attempts left: {remaining_attempts}")

        if remaining_attempts > 0:
            # Inform the user about the failed attempt and remaining attempts
            messagebox.showerror(
                "Authentication Failed",
                f"Invalid USB authentication data. Attempts remaining: {remaining_attempts}."
            )
        else:
            # User has exceeded maximum attempts; initiate lockout
            state["lockout_time"] = current_time + LOCKOUT_DURATION  # Set lockout end time
            messagebox.showerror(
                "Authentication Locked",
                f"Too many failed attempts. Locked out for {LOCKOUT_DURATION // 60} minutes."
            )
            logging.error(f"User locked out until {time.ctime(state['lockout_time'])} due to too many failed attempts.")
            # Optional: Implement email alert or other notification mechanisms here

            state["failed_attempts"] = 0  # Reset failed attempts after lockout

        save_auth_state(state)  # Save the updated authentication state
        root.destroy()
        return False

# -------------------- Main Function for Standalone Testing --------------------

if __name__ == "__main__":
    """
    For standalone testing purposes.
    Attempts to authenticate the USB and prints the result to the console.
    """
    if authenticate_usb():
        print("Authentication succeeded. Proceeding with application launch.")
    else:
        print("Authentication failed. Application will exit.")
