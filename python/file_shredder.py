# file_shredder.py

import os
import logging
import secrets
import shutil
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

# Set up logging to a file
logging.basicConfig(
    filename="shredder.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def shred_file(file_path, num_passes=3, save_shredded_content=False,
               save_directory=None, base_path=None, progress_callback=None):
    """
    Securely shred a file by overwriting it multiple times and then deleting it.

    Parameters:
    - file_path: Path to the file to be shredded.
    - num_passes: Number of overwrite passes.
    - save_shredded_content: If True, saves shredded content.
    - save_directory: Directory where shredded files will be saved (used when shredding directories).
    - base_path: Base path to calculate relative paths (used when shredding directories).
    - progress_callback: Function to update progress bar in the GUI.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        buffer_size = 65536  # 64KB buffer

        with open(file_path, "r+b") as f:
            for pass_num in range(1, num_passes + 1):
                f.seek(0)
                bytes_written = 0
                while bytes_written < file_size:
                    chunk_size = min(buffer_size, file_size - bytes_written)
                    if pass_num < num_passes:
                        # Overwrite with predefined patterns
                        pattern = (pass_num % 256)
                        data = bytes([pattern]) * chunk_size
                    else:
                        # Final pass with random data
                        data = os.urandom(chunk_size)
                    f.write(data)
                    bytes_written += chunk_size
                f.flush()
                os.fsync(f.fileno())
                logging.info(f"Pass {pass_num}/{num_passes} completed for file: {file_path}")

                if progress_callback:
                    progress_callback(pass_num, num_passes)

        if save_shredded_content:
            if save_directory:
                # Save shredded file to the specified directory, preserving the directory structure
                if base_path:
                    relative_path = os.path.relpath(file_path, start=base_path)
                else:
                    relative_path = os.path.basename(file_path)
                destination_path = os.path.join(save_directory, relative_path)
                os.makedirs(os.path.dirname(destination_path), exist_ok=True)
                shutil.move(file_path, destination_path)
                logging.info(f"Shredded content saved as: {destination_path}")
            else:
                # Ask the user where to save the shredded content
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".shredded",
                    initialfile=os.path.basename(file_path),
                    filetypes=[("All Files", "*.*")],
                    title="Save Shredded Content As"
                )

                if save_path:
                    shutil.move(file_path, save_path)
                    logging.info(f"Shredded content saved as: {save_path}")
                else:
                    os.remove(file_path)
                    logging.info(f"File shredded and deleted, not saved.")
        else:
            os.remove(file_path)
            logging.info(f"File shredded and deleted: {file_path}")

        return True

    except FileNotFoundError as e:
        logging.error(f"File not found error: {str(e)}")
        messagebox.showerror("File Error", f"File not found: {file_path}")
        return False
    except PermissionError as e:
        logging.error(f"Permission error: {str(e)}")
        messagebox.showerror("Permission Error", f"Permission denied: {str(e)}")
        return False
    except IOError as e:
        logging.error(f"I/O error: {str(e)}")
        messagebox.showerror("I/O Error", f"An error occurred while shredding the file: {str(e)}")
        return False
    except Exception as e:
        logging.error(f"General error: {str(e)}")
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
        return False


def shred_directory(directory_path, num_passes=3, save_shredded_content=False, progress_callback=None):
    """
    Securely shred all files in a directory recursively.

    Parameters:
    - directory_path: Path to the directory to be shredded.
    - num_passes: Number of overwrite passes.
    - save_shredded_content: If True, saves shredded content.
    - progress_callback: Function to update progress bar in the GUI.
    """
    try:
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # Collect all files to be shredded
        files_to_shred = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                files_to_shred.append(os.path.join(root, file))

        total_files = len(files_to_shred)
        total_passes = total_files * num_passes
        current_progress = [0]  # Use a list to allow modification inside nested function

        # If saving shredded content, ask for a directory to save them
        save_directory = None
        if save_shredded_content:
            while True:
                save_directory = filedialog.askdirectory(title="Select Directory to Save Shredded Files")
                if not save_directory:
                    # User cancelled the operation
                    logging.info("No directory selected to save shredded files.")
                    return False

                if is_subdirectory(save_directory, directory_path) or os.path.abspath(save_directory) == os.path.abspath(directory_path):
                    messagebox.showerror(
                        "Invalid Save Location",
                        "The save directory cannot be the same as or a subdirectory of the directory being shredded. Please choose a different location."
                    )
                else:
                    break  # Valid directory selected

        for file_index, file_path in enumerate(files_to_shred):
            def dir_progress_callback(current_pass, total_passes_per_file):
                progress_callback(
                    current_progress[0] + current_pass,
                    total_passes
                )

            shred_file(
                file_path,
                num_passes=num_passes,
                save_shredded_content=save_shredded_content,
                save_directory=save_directory,
                base_path=directory_path,
                progress_callback=dir_progress_callback
            )
            current_progress[0] += num_passes  # Update progress after each file

        # Remove empty directories if not saving shredded content
        if not save_shredded_content:
            shutil.rmtree(directory_path)
            logging.info(f"Directory securely shredded and deleted: {directory_path}")

        return True

    except FileNotFoundError as e:
        logging.error(f"Directory not found error: {str(e)}")
        messagebox.showerror("Directory Error", f"Directory not found: {directory_path}")
        return False
    except PermissionError as e:
        logging.error(f"Permission error: {str(e)}")
        messagebox.showerror("Permission Error", f"Permission denied: {str(e)}")
        return False
    except IOError as e:
        logging.error(f"I/O error: {str(e)}")
        messagebox.showerror("I/O Error", f"An error occurred while shredding the directory: {str(e)}")
        return False
    except Exception as e:
        logging.error(f"General error: {str(e)}")
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
        return False


def is_subdirectory(child, parent):
    """
    Check if 'child' is the same as or a subdirectory of 'parent'.

    Parameters:
    - child: Path of the child directory.
    - parent: Path of the parent directory.

    Returns:
    - True if 'child' is the same as or a subdirectory of 'parent', False otherwise.
    """
    parent = os.path.abspath(parent)
    child = os.path.abspath(child)
    return os.path.commonpath([parent]) == os.path.commonpath([parent, child])


# GUI Code using customtkinter

def open_shredding_menu(master):
    """
    Open a window with all shredding-related options.

    Parameters:
    - master: The parent Tkinter window.
    """
    shredding_window = ctk.CTkToplevel(master)
    shredding_window.title("Shredding Menu")
    shredding_window.geometry("500x400")
    shredding_window.resizable(False, False)

    ctk.CTkLabel(
        shredding_window,
        text="Shredding Options",
        font=ctk.CTkFont(size=20, weight="bold")
    ).pack(pady=20)

    ctk.CTkButton(
        shredding_window,
        text="Shred a File",
        command=lambda: open_file_shredder_dialog(shredding_window),
        width=200,
        height=40
    ).pack(pady=10)

    ctk.CTkButton(
        shredding_window,
        text="Shred a Directory",
        command=lambda: open_directory_shredder_dialog(shredding_window),
        width=200,
        height=40
    ).pack(pady=10)

    ctk.CTkButton(
        shredding_window,
        text="Close",
        command=shredding_window.destroy,
        width=150,
        height=30
    ).pack(pady=20)


def open_file_shredder_dialog(master):
    """
    Open a file dialog to manually shred a selected file.

    Parameters:
    - master: The parent Tkinter window.
    """
    file_path = filedialog.askopenfilename(title="Select a file to shred")

    if file_path:
        absolute_file_path = os.path.abspath(file_path)
        logging.info(f"File selected for shredding: {absolute_file_path}")

        # Ask for the number of passes and whether to save shredded content
        num_passes, save_content = ask_shredding_options(master)
        if num_passes is None:
            logging.info("Shredding operation cancelled by user.")
            return

        result = messagebox.askyesno(
            "Confirm Shredding",
            f"Are you sure you want to securely shred the file '{absolute_file_path}' with {num_passes} passes?"
        )
        if result:
            progress_window = create_progress_window(master, "Shredding File...")
            threading.Thread(
                target=shred_file_thread,
                args=(absolute_file_path, num_passes, save_content, progress_window)
            ).start()
        else:
            logging.info(f"Shredding operation cancelled for file: {absolute_file_path}")
    else:
        logging.error("No file selected for shredding.")


def open_directory_shredder_dialog(master):
    """
    Open a directory dialog to shred all files in a selected directory.

    Parameters:
    - master: The parent Tkinter window.
    """
    directory_path = filedialog.askdirectory(title="Select a directory to shred")

    if directory_path:
        absolute_directory_path = os.path.abspath(directory_path)
        logging.info(f"Directory selected for shredding: {absolute_directory_path}")

        # Ask for the number of passes and whether to save shredded content
        num_passes, save_content = ask_shredding_options(master, is_directory=True)
        if num_passes is None:
            logging.info("Shredding operation cancelled by user.")
            return

        result = messagebox.askyesno(
            "Confirm Shredding",
            f"Are you sure you want to securely shred the directory '{absolute_directory_path}' and all its contents with {num_passes} passes?"
        )
        if result:
            progress_window = create_progress_window(master, "Shredding Directory...")
            threading.Thread(
                target=shred_directory_thread,
                args=(absolute_directory_path, num_passes, save_content, progress_window)
            ).start()
        else:
            logging.info(f"Shredding operation cancelled for directory: {absolute_directory_path}")
    else:
        logging.error("No directory selected for shredding.")


def ask_shredding_options(master, is_directory=False):
    """
    Prompt the user to select the number of shredding passes and whether to save shredded content.

    Parameters:
    - master: The parent Tkinter window.
    - is_directory: Boolean indicating if the options are for a directory.

    Returns:
    - A tuple (num_passes, save_shredded_content) or (None, None) if cancelled.
    """
    dialog = ctk.CTkToplevel(master)
    dialog.title("Shredding Options")
    dialog.geometry("350x250")
    dialog.resizable(False, False)

    ctk.CTkLabel(dialog, text="Enter the number of shredding passes (1-35):", font=ctk.CTkFont(size=14)).pack(pady=10)

    num_passes_var = ctk.StringVar(value="3")
    entry = ctk.CTkEntry(dialog, textvariable=num_passes_var, width=50)
    entry.pack(pady=5)

    save_content_var = ctk.BooleanVar(value=False)
    if is_directory:
        ctk.CTkLabel(dialog, text="Save shredded content?", font=ctk.CTkFont(size=14)).pack(pady=10)
        ctk.CTkCheckBox(dialog, text="Yes", variable=save_content_var).pack()
    else:
        # For files, always ask to save shredded content
        save_content_var.set(True)

    def on_confirm():
        num_passes_str = num_passes_var.get()
        try:
            num_passes = int(num_passes_str)
            if num_passes < 1 or num_passes > 35:
                raise ValueError
            dialog.destroy()
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number of passes between 1 and 35.")

    def on_cancel():
        num_passes_var.set("0")
        dialog.destroy()

    button_frame = ctk.CTkFrame(dialog)
    button_frame.pack(pady=20)

    ctk.CTkButton(button_frame, text="Confirm", command=on_confirm, width=80).pack(side="left", padx=10)
    ctk.CTkButton(button_frame, text="Cancel", command=on_cancel, width=80).pack(side="right", padx=10)

    dialog.wait_window()

    num_passes_str = num_passes_var.get()
    try:
        num_passes = int(num_passes_str)
        if num_passes > 0:
            return num_passes, save_content_var.get()
        else:
            return None, None
    except ValueError:
        return None, None


def create_progress_window(master, title):
    """
    Create a window with a progress bar to display shredding progress.

    Parameters:
    - master: The parent Tkinter window.
    - title: Title of the progress window.

    Returns:
    - An instance of ProgressWindow class.
    """
    progress_window = ctk.CTkToplevel(master)
    progress_window.title(title)
    progress_window.geometry("400x150")
    progress_window.resizable(False, False)

    ctk.CTkLabel(progress_window, text=title, font=ctk.CTkFont(size=16)).pack(pady=10)

    progress_bar = ctk.CTkProgressBar(progress_window, width=300)
    progress_bar.set(0)
    progress_bar.pack(pady=10)

    class ProgressWindow:
        def __init__(self, window, progress_bar):
            self.window = window
            self.progress_bar = progress_bar

        def update_progress(self, current, total):
            self.progress_bar.set(current / total)
            self.window.update_idletasks()

        def close(self):
            self.window.destroy()

    return ProgressWindow(progress_window, progress_bar)


def shred_file_thread(file_path, num_passes, save_content, progress_window):
    """
    Thread function to shred a file without blocking the GUI.

    Parameters:
    - file_path: Path to the file to be shredded.
    - num_passes: Number of overwrite passes.
    - save_content: Whether to save shredded content.
    - progress_window: Instance of ProgressWindow to update progress.
    """
    shred_status = shred_file(
        file_path,
        num_passes=num_passes,
        save_shredded_content=save_content,
        progress_callback=progress_window.update_progress
    )
    progress_window.close()

    if shred_status:
        messagebox.showinfo(
            "Shred Complete",
            f"File '{file_path}' securely shredded."
        )
    else:
        messagebox.showerror(
            "Shred Error",
            f"Failed to shred the file '{file_path}'. Check logs for details."
        )


def shred_directory_thread(directory_path, num_passes, save_content, progress_window):
    """
    Thread function to shred a directory without blocking the GUI.

    Parameters:
    - directory_path: Path to the directory to be shredded.
    - num_passes: Number of overwrite passes.
    - save_content: Whether to save shredded content.
    - progress_window: Instance of ProgressWindow to update progress.
    """
    shred_status = shred_directory(
        directory_path,
        num_passes=num_passes,
        save_shredded_content=save_content,
        progress_callback=progress_window.update_progress
    )
    progress_window.close()

    if shred_status:
        messagebox.showinfo(
            "Shred Complete",
            f"Directory '{directory_path}' and all its contents securely shredded."
        )
    else:
        messagebox.showerror(
            "Shred Error",
            f"Failed to shred the directory '{directory_path}'. Check logs for details."
        )
