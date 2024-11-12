# usb_auth_handle.py

import os
import hashlib
import json
import time
import logging
import importlib.util
from tkinter import messagebox, Tk
import win32api  # Requires PyWin32

# -------------------- Configuration --------------------

# Configuration for USB Authentication
USB_VOLUME_LABEL = "TESTER"  # Replace with your USB's volume label
USB_SCRIPT_NAME = "usb_auth.py"
EXPECTED_HASH = "c2396e47a3f4b3df4e1be9ae3c400876f804ac5dedd1b46e83477e92fad4487f"
EXPECTED_CHECKSUM = "791b4a1df4a7d27a7b82825ba0c83bae6f238921e70fa8d9ec8332abe7ef69a5"

MAX_ATTEMPTS = 5  # Maximum number of attempts before lockout
LOCKOUT_DURATION = 600  # Lockout duration in seconds (10 minutes)
AUTH_STATE_FILE = "auth_state.json"
LOG_FILE = "auth.log"

# -------------------- Setup Logging --------------------

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -------------------- Authentication State Management --------------------

def load_auth_state():
    """
    Loads the authentication state from a JSON file.
    """
    if os.path.exists(AUTH_STATE_FILE):
        try:
            with open(AUTH_STATE_FILE, 'r') as f:
                state = json.load(f)
                return state
        except Exception as e:
            logging.error(f"Failed to load auth state: {e}")
    # Default state
    return {"failed_attempts": 0, "lockout_time": 0}

def save_auth_state(state):
    """
    Saves the authentication state to a JSON file.
    """
    try:
        with open(AUTH_STATE_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        logging.error(f"Failed to save auth state: {e}")

# -------------------- USB Detection --------------------

def find_usb_path():
    """
    Finds the USB drive path based on the volume label.
    Returns the full path to the usb_auth.py script if found, else None.
    """
    try:
        drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
        for drive in drives:
            try:
                vol_info = win32api.GetVolumeInformation(drive)
                volume_label = vol_info[0]
                if volume_label == USB_VOLUME_LABEL:
                    usb_path = os.path.join(drive, USB_SCRIPT_NAME)
                    if os.path.exists(usb_path):
                        return usb_path
            except Exception:
                continue
    except Exception as e:
        logging.error(f"Error detecting USB drives: {e}")
    return None

# -------------------- Integrity Verification --------------------

def compute_file_checksum(file_path):
    """
    Computes the SHA-256 checksum of a given file.
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
    Loads and returns the hashed authentication data from usb_auth.py on the USB.
    """
    try:
        # Verify the integrity of usb_auth.py
        actual_checksum = compute_file_checksum(usb_path)
        if actual_checksum != EXPECTED_CHECKSUM:
            logging.warning("usb_auth.py checksum mismatch. Possible tampering detected.")
            messagebox.showerror("Authentication Error", "USB authentication script integrity check failed.")
            return None

        # Dynamically import usb_auth.py
        spec = importlib.util.spec_from_file_location("usb_auth", usb_path)
        usb_auth = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(usb_auth)

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
    Returns True if authentication is successful, False otherwise.
    """
    # Initialize Tkinter root (hidden)
    root = Tk()
    root.withdraw()

    state = load_auth_state()
    current_time = time.time()

    # Check if currently locked out
    if state["lockout_time"] > current_time:
        remaining_time = int(state["lockout_time"] - current_time)
        minutes, seconds = divmod(remaining_time, 60)
        messagebox.showwarning(
            "Authentication Locked",
            f"Too many failed attempts. Please try again in {minutes} minutes and {seconds} seconds."
        )
        root.destroy()
        return False

    usb_path = find_usb_path()

    if not usb_path:
        messagebox.showerror(
            "USB Not Found",
            f"USB not found. Please insert the correct USB and try again."
        )
        logging.warning("USB drive not found.")
        root.destroy()
        return False

    usb_hashed_data = load_usb_auth_data(usb_path)

    if usb_hashed_data is None:
        # Error message already shown in load_usb_auth_data
        root.destroy()
        return False

    if usb_hashed_data == EXPECTED_HASH:
        logging.info("Authentication successful.")
        state["failed_attempts"] = 0
        state["lockout_time"] = 0
        save_auth_state(state)
        messagebox.showinfo("Authentication Successful", "USB authentication successful.")
        root.destroy()
        return True
    else:
        state["failed_attempts"] += 1
        remaining_attempts = MAX_ATTEMPTS - state["failed_attempts"]
        logging.warning(f"Authentication failed. Attempts left: {remaining_attempts}")

        if remaining_attempts > 0:
            messagebox.showerror(
                "Authentication Failed",
                f"Invalid USB authentication data. Attempts remaining: {remaining_attempts}."
            )
        else:
            state["lockout_time"] = current_time + LOCKOUT_DURATION
            messagebox.showerror(
                "Authentication Locked",
                f"Too many failed attempts. Locked out for {LOCKOUT_DURATION // 60} minutes."
            )
            logging.error(f"User locked out until {time.ctime(state['lockout_time'])} due to too many failed attempts.")
            # Optional: Implement email alert or other notification mechanisms here

            state["failed_attempts"] = 0  # Reset after lockout

        save_auth_state(state)
        root.destroy()
        return False

# -------------------- Main Function for Standalone Testing --------------------

if __name__ == "__main__":
    """
    For standalone testing purposes.
    """
    if authenticate_usb():
        print("Authentication succeeded. Proceeding with application launch.")
    else:
        print("Authentication failed. Application will exit.")
