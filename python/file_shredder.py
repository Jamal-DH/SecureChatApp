import os
import logging
import secrets
import shutil
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

# -------------------------------------------------------------
# Set up logging to a file named "shredder.log" with INFO level.
# Logs will record timestamps, log level, and the message.
# -------------------------------------------------------------
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
    - save_shredded_content: If True, saves shredded content instead of deleting.
    - save_directory: Directory where shredded files will be saved 
                      (used when shredding directories).
    - base_path: Base path to calculate relative paths (used when shredding directories).
    - progress_callback: Optional function to update a progress bar in the GUI.

    Returns:
    - True if shredding is successful, False otherwise.
    """
    try:
        # -------------------------------------------------------------
        # Check if the file exists. If not, raise FileNotFoundError.
        # -------------------------------------------------------------
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # -------------------------------------------------------------
        # Determine the size of the file and set a buffer for overwriting.
        # -------------------------------------------------------------
        file_size = os.path.getsize(file_path)
        buffer_size = 65536  # 64KB buffer

        # -------------------------------------------------------------
        # Open the file in read+binary mode to overwrite its contents.
        # -------------------------------------------------------------
        with open(file_path, "r+b") as f:
            # -------------------------------------------------------------
            # Perform multiple overwrite passes. Each pass overwrites 
            # the entire file.
            # -------------------------------------------------------------
            for pass_num in range(1, num_passes + 1):
                f.seek(0)  # Move file pointer to the start.
                bytes_written = 0

                # -------------------------------------------------------------
                # Overwrite the file chunk by chunk until all data is overwritten.
                # -------------------------------------------------------------
                while bytes_written < file_size:
                    chunk_size = min(buffer_size, file_size - bytes_written)
                    if pass_num < num_passes:
                        # Overwrite with a simple repeating pattern.
                        pattern = (pass_num % 256)
                        data = bytes([pattern]) * chunk_size
                    else:
                        # Final pass uses random data for more security.
                        data = os.urandom(chunk_size)

                    f.write(data)
                    bytes_written += chunk_size

                # -------------------------------------------------------------
                # Force write to disk, ensuring data isn't just cached.
                # -------------------------------------------------------------
                f.flush()
                os.fsync(f.fileno())

                logging.info(f"Pass {pass_num}/{num_passes} completed for file: {file_path}")

                # -------------------------------------------------------------
                # If a progress callback is provided, call it to update any 
                # progress bar or indicator in the GUI.
                # -------------------------------------------------------------
                if progress_callback:
                    progress_callback(pass_num, num_passes)

        # -------------------------------------------------------------
        # If the user wants to save shredded content, move the file 
        # to the specified or chosen location. Otherwise, delete it.
        # -------------------------------------------------------------
        if save_shredded_content:
            if save_directory:
                # -------------------------------------------------------------
                # Calculate a relative path if base_path is provided, 
                # preserving the directory structure in the save directory.
                # -------------------------------------------------------------
                if base_path:
                    relative_path = os.path.relpath(file_path, start=base_path)
                else:
                    relative_path = os.path.basename(file_path)

                destination_path = os.path.join(save_directory, relative_path)
                os.makedirs(os.path.dirname(destination_path), exist_ok=True)
                shutil.move(file_path, destination_path)
                logging.info(f"Shredded content saved as: {destination_path}")
            else:
                # -------------------------------------------------------------
                # If no directory is specified, ask the user where to save 
                # the shredded file. If the user cancels, remove the file.
                # -------------------------------------------------------------
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
    - save_shredded_content: If True, saves shredded content instead of deleting.
    - progress_callback: Optional function to update a progress bar in the GUI.

    Returns:
    - True if shredding is successful, False otherwise.
    """
    try:
        # -------------------------------------------------------------
        # Check if the directory exists. If not, raise FileNotFoundError.
        # -------------------------------------------------------------
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # -------------------------------------------------------------
        # Collect all files in the directory (and subdirectories) to shred.
        # -------------------------------------------------------------
        files_to_shred = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                files_to_shred.append(os.path.join(root, file))

        # -------------------------------------------------------------
        # Calculate the total number of passes for the entire directory.
        # Each file has num_passes passes.
        # -------------------------------------------------------------
        total_files = len(files_to_shred)
        total_passes = total_files * num_passes

        # -------------------------------------------------------------
        # Use a list for current_progress so it can be modified from 
        # an inner function.
        # -------------------------------------------------------------
        current_progress = [0]

        # -------------------------------------------------------------
        # If the user wants to save shredded content, ask for a directory
        # to store all the shredded files. Ensure it's not the same or
        # a subdirectory of the directory being shredded.
        # -------------------------------------------------------------
        save_directory = None
        if save_shredded_content:
            while True:
                save_directory = filedialog.askdirectory(title="Select Directory to Save Shredded Files")
                if not save_directory:
                    # -------------------------------------------------------------
                    # If no directory is chosen, consider the operation cancelled.
                    # -------------------------------------------------------------
                    logging.info("No directory selected to save shredded files.")
                    return False

                # -------------------------------------------------------------
                # Check that save_directory is not the directory itself or 
                # a subdirectory of it.
                # -------------------------------------------------------------
                if is_subdirectory(save_directory, directory_path) or os.path.abspath(save_directory) == os.path.abspath(directory_path):
                    messagebox.showerror(
                        "Invalid Save Location",
                        "The save directory cannot be the same as or a subdirectory of the directory being shredded. Please choose a different location."
                    )
                else:
                    break  # Valid directory selected

        # -------------------------------------------------------------
        # Shred each file. Update progress after each file is done.
        # -------------------------------------------------------------
        for file_index, file_path in enumerate(files_to_shred):
            # -------------------------------------------------------------
            # Define a nested function to update the overall progress
            # for the entire directory shredding process.
            # -------------------------------------------------------------
            def dir_progress_callback(current_pass, total_passes_per_file):
                progress_callback(
                    current_progress[0] + current_pass,
                    total_passes
                )

            # -------------------------------------------------------------
            # Shred the file, passing the nested callback function 
            # and relevant parameters.
            # -------------------------------------------------------------
            shred_file(
                file_path,
                num_passes=num_passes,
                save_shredded_content=save_shredded_content,
                save_directory=save_directory,
                base_path=directory_path,
                progress_callback=dir_progress_callback
            )
            # -------------------------------------------------------------
            # After each file is shredded, add num_passes to the current 
            # total progress.
            # -------------------------------------------------------------
            current_progress[0] += num_passes

        # -------------------------------------------------------------
        # If we are not saving shredded content, remove the original 
        # directory structure after all files are shredded.
        # -------------------------------------------------------------
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
    - True if 'child' is the same as or a subdirectory of 'parent', 
      False otherwise.
    """
    parent = os.path.abspath(parent)
    child = os.path.abspath(child)
    # -------------------------------------------------------------
    # commonpath returns the shared path between two paths. 
    # If child is a subdirectory of parent, they share the same 
    # commonpath as parent.
    # -------------------------------------------------------------
    return os.path.commonpath([parent]) == os.path.commonpath([parent, child])

# -------------------------------------------------------------
# Below is the GUI code built using CustomTkinter (ctk) for 
# interacting with the user. It provides dialogs and windows 
# for selecting files/directories and configuring shred options.
# -------------------------------------------------------------

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

        # -------------------------------------------------------------
        # Prompt the user for shredding passes and whether to save the 
        # shredded content.
        # -------------------------------------------------------------
        num_passes, save_content = ask_shredding_options(master)
        if num_passes is None:
            logging.info("Shredding operation cancelled by user.")
            return

        # -------------------------------------------------------------
        # Confirm with the user before proceeding to shred.
        # -------------------------------------------------------------
        result = messagebox.askyesno(
            "Confirm Shredding",
            f"Are you sure you want to securely shred the file '{absolute_file_path}' with {num_passes} passes?"
        )
        if result:
            # -------------------------------------------------------------
            # Create a separate window to display the progress bar and 
            # run the shredding in a new thread (so the UI remains responsive).
            # -------------------------------------------------------------
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

        # -------------------------------------------------------------
        # Prompt user for number of passes and whether to save content.
        # -------------------------------------------------------------
        num_passes, save_content = ask_shredding_options(master, is_directory=True)
        if num_passes is None:
            logging.info("Shredding operation cancelled by user.")
            return

        # -------------------------------------------------------------
        # Confirm with the user before proceeding to shred the directory.
        # -------------------------------------------------------------
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
    Prompt the user to select the number of shredding passes 
    and whether to save shredded content.

    Parameters:
    - master: The parent Tkinter window.
    - is_directory: Boolean indicating if the options are for a directory.

    Returns:
    - A tuple (num_passes, save_shredded_content) 
      or (None, None) if the user cancels.
    """
    dialog = ctk.CTkToplevel(master)
    dialog.title("Shredding Options")
    dialog.geometry("350x250")
    dialog.resizable(False, False)

    ctk.CTkLabel(dialog, text="Enter the number of shredding passes (1-35):", 
                 font=ctk.CTkFont(size=14)).pack(pady=10)

    num_passes_var = ctk.StringVar(value="3")
    entry = ctk.CTkEntry(dialog, textvariable=num_passes_var, width=50)
    entry.pack(pady=5)

    # -------------------------------------------------------------
    # For directories, let the user decide if shredded content 
    # should be saved. For files, it's always asked (default True).
    # -------------------------------------------------------------
    save_content_var = ctk.BooleanVar(value=False)
    if is_directory:
        ctk.CTkLabel(dialog, text="Save shredded content?", font=ctk.CTkFont(size=14)).pack(pady=10)
        ctk.CTkCheckBox(dialog, text="Yes", variable=save_content_var).pack()
    else:
        save_content_var.set(True)

    def on_confirm():
        # -------------------------------------------------------------
        # Validate the number of passes. Must be between 1 and 35.
        # -------------------------------------------------------------
        num_passes_str = num_passes_var.get()
        try:
            num_passes = int(num_passes_str)
            if num_passes < 1 or num_passes > 35:
                raise ValueError
            dialog.destroy()
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number of passes between 1 and 35.")

    def on_cancel():
        # -------------------------------------------------------------
        # If the user cancels, set num_passes_var to '0' which triggers 
        # the return (None, None) logic outside.
        # -------------------------------------------------------------
        num_passes_var.set("0")
        dialog.destroy()

    button_frame = ctk.CTkFrame(dialog)
    button_frame.pack(pady=20)

    ctk.CTkButton(button_frame, text="Confirm", command=on_confirm, width=80).pack(side="left", padx=10)
    ctk.CTkButton(button_frame, text="Cancel", command=on_cancel, width=80).pack(side="right", padx=10)

    # -------------------------------------------------------------
    # Wait until the dialog is closed before returning.
    # -------------------------------------------------------------
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
    - An instance of an inner class 'ProgressWindow' that provides
      methods to update and close the progress window.
    """
    progress_window = ctk.CTkToplevel(master)
    progress_window.title(title)
    progress_window.geometry("400x150")
    progress_window.resizable(False, False)

    ctk.CTkLabel(progress_window, text=title, font=ctk.CTkFont(size=16)).pack(pady=10)

    # -------------------------------------------------------------
    # Initialize the progress bar at 0%. 
    # -------------------------------------------------------------
    progress_bar = ctk.CTkProgressBar(progress_window, width=300)
    progress_bar.set(0)
    progress_bar.pack(pady=10)

    # -------------------------------------------------------------
    # Inner class to wrap the progress bar functionality and 
    # progress window handling.
    # -------------------------------------------------------------
    class ProgressWindow:
        def __init__(self, window, progress_bar):
            self.window = window
            self.progress_bar = progress_bar

        def update_progress(self, current, total):
            """
            Update the progress bar based on current and total passes.
            """
            self.progress_bar.set(current / total)
            # -------------------------------------------------------------
            # update_idletasks ensures the UI updates immediately 
            # instead of waiting for the main loop to be idle.
            # -------------------------------------------------------------
            self.window.update_idletasks()

        def close(self):
            """Close the progress window."""
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
    # -------------------------------------------------------------
    # Perform the file shredding in a separate thread, then 
    # close the progress window when done.
    # -------------------------------------------------------------
    shred_status = shred_file(
        file_path,
        num_passes=num_passes,
        save_shredded_content=save_content,
        progress_callback=progress_window.update_progress
    )
    progress_window.close()

    # -------------------------------------------------------------
    # Provide feedback to the user depending on success or failure.
    # -------------------------------------------------------------
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
    # -------------------------------------------------------------
    # Perform the directory shredding in a separate thread, then 
    # close the progress window when done.
    # -------------------------------------------------------------
    shred_status = shred_directory(
        directory_path,
        num_passes=num_passes,
        save_shredded_content=save_content,
        progress_callback=progress_window.update_progress
    )
    progress_window.close()

    # -------------------------------------------------------------
    # Notify the user of the outcome via a message box.
    # -------------------------------------------------------------
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
