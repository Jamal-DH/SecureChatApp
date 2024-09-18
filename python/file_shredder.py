import os
import logging
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, Label, Button, Checkbutton, BooleanVar
from tkinter.ttk import Progressbar
import shutil

# Shredding settings
skip_shredding = False

# Set up logging to a file
logging.basicConfig(filename="shredder.log", level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def shred_file(file_path, progress_callback=None):
    """Securely shred a file using the Gutmann method, ensuring full overwrite of original content."""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)

        # 35-pass Gutmann method patterns
        gutmann_patterns = [
            b'\x55' * file_size, b'\xAA' * file_size,
            b'\x92\x49\x24' * (file_size // 3), b'\x49\x24\x92' * (file_size // 3), b'\x24\x92\x49' * (file_size // 3),
            b'\x00' * file_size, b'\x11' * file_size, b'\x22' * file_size, b'\x33' * file_size,
            b'\x44' * file_size, b'\x55' * file_size, b'\x66' * file_size, b'\x77' * file_size,
            b'\x88' * file_size, b'\x99' * file_size, b'\xAA' * file_size, b'\xBB' * file_size,
            b'\xCC' * file_size, b'\xDD' * file_size, b'\xEE' * file_size, b'\xFF' * file_size,
            b'\x92\x49\x24' * (file_size // 3), b'\x49\x24\x92' * (file_size // 3), b'\x24\x92\x49' * (file_size // 3),
            secrets.token_bytes(file_size), secrets.token_bytes(file_size), secrets.token_bytes(file_size),
            secrets.token_bytes(file_size), secrets.token_bytes(file_size), secrets.token_bytes(file_size),
            secrets.token_bytes(file_size), secrets.token_bytes(file_size), secrets.token_bytes(file_size),
            secrets.token_bytes(file_size)
        ]

        with open(file_path, "r+b") as f:
            for pass_num, pattern in enumerate(gutmann_patterns, 1):
                f.seek(0)  # Ensure we start writing at the beginning of the file
                f.write(pattern[:file_size])  # Overwrite the entire file with the current pattern
                f.flush()
                os.fsync(f.fileno())  # Ensure data is written to disk
                logging.info(f"Pass {pass_num}/35 completed for file: {file_path}")

                if progress_callback:
                    progress_callback(pass_num, 35)

        # Ask the user where to save the shredded content
        save_path = filedialog.asksaveasfilename(defaultextension=".shredded",
                                                 filetypes=[("All Files", "*.*")],
                                                 title="Save Shredded Content As")

        if save_path:
            shutil.move(file_path, save_path)
            logging.info(f"Shredded content saved as: {save_path}")
        else:
            os.remove(file_path)
            logging.info(f"File shredded and deleted, not saved.")

        return True

    except FileNotFoundError as e:
        logging.error(f"File not found error: {str(e)}")
        messagebox.showerror("File Error", f"File not found: {file_path}")
        return False
    except IOError as e:
        logging.error(f"IO error: {str(e)}")
        messagebox.showerror("I/O Error", f"An error occurred while shredding the file: {str(e)}")
        return False
    except Exception as e:
        logging.error(f"General error: {str(e)}")
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
        return False

def shred_directory(directory_path, progress_callback=None):
    """Securely shred all files in a directory recursively using the Gutmann method."""
    try:
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        total_files = sum([len(files) for _, _, files in os.walk(directory_path)])
        shredded_files = 0

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                shred_file(file_path, progress_callback=lambda _, __: progress_callback(shredded_files + 1, total_files))
                shredded_files += 1

        os.rmdir(directory_path)
        logging.info(f"Directory securely shredded: {directory_path}")
        return True

    except FileNotFoundError as e:
        logging.error(f"Directory not found error: {str(e)}")
        messagebox.showerror("Directory Error", f"Directory not found: {directory_path}")
        return False
    except IOError as e:
        logging.error(f"IO error: {str(e)}")
        messagebox.showerror("I/O Error", f"An error occurred while shredding the directory: {str(e)}")
        return False
    except Exception as e:
        logging.error(f"General error: {str(e)}")
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
        return False



def open_file_shredder_dialog(master):
    """Open a file dialog to manually shred a selected file."""
    file_path = filedialog.askopenfilename(title="Select a file to shred")

    if file_path:
        absolute_file_path = os.path.abspath(file_path)
        logging.info(f"File selected for shredding: {absolute_file_path}")

        result = messagebox.askyesno("Confirm Shredding",
                                     f"Are you sure you want to securely shred the file '{absolute_file_path}' using the Gutmann method?")
        if result:
            progress_window = create_progress_window(master, "Shredding File...")
            shred_status = shred_file(absolute_file_path, progress_callback=progress_window.update_progress)
            progress_window.close()

            if shred_status:
                messagebox.showinfo("Shred Complete", f"File '{absolute_file_path}' securely shredded.")
            else:
                messagebox.showerror("Shred Error", f"Failed to shred the file '{absolute_file_path}'. Check logs for details.")
        else:
            logging.info(f"Shredding operation cancelled for file: {absolute_file_path}")
    else:
        logging.error(f"No file selected for shredding.")

def open_directory_shredder_dialog(master):
    """Open a directory dialog to shred all files in a selected directory."""
    directory_path = filedialog.askdirectory(title="Select a directory to shred")

    if directory_path:
        absolute_directory_path = os.path.abspath(directory_path)
        logging.info(f"Directory selected for shredding: {absolute_directory_path}")

        result = messagebox.askyesno("Confirm Shredding",
                                     f"Are you sure you want to securely shred the directory '{absolute_directory_path}' and all its contents using the Gutmann method?")
        if result:
            progress_window = create_progress_window(master, "Shredding Directory...")
            shred_status = shred_directory(absolute_directory_path, progress_callback=progress_window.update_progress)
            progress_window.close()

            if shred_status:
                messagebox.showinfo("Shred Complete", f"Directory '{absolute_directory_path}' and all its contents securely shredded.")
            else:
                messagebox.showerror("Shred Error", f"Failed to shred the directory '{absolute_directory_path}'. Check logs for details.")
        else:
            logging.info(f"Shredding operation cancelled for directory: {absolute_directory_path}")
    else:
        logging.error(f"No directory selected for shredding.")

def create_progress_window(master, title):
    """Create a window with a progress bar to display shredding progress."""
    progress_window = Toplevel(master)
    progress_window.title(title)
    progress_window.geometry("400x100")

    Label(progress_window, text=title).pack(pady=10)

    progress_bar = Progressbar(progress_window, orient="horizontal", length=300, mode="determinate")
    progress_bar.pack(pady=10)

    class ProgressWindow:
        def __init__(self, window, progress_bar):
            self.window = window
            self.progress_bar = progress_bar

        def update_progress(self, current, total):
            self.progress_bar['value'] = (current / total) * 100
            self.window.update_idletasks()

        def close(self):
            self.window.destroy()

    return ProgressWindow(progress_window, progress_bar)

def open_shredding_menu(master):
    """Open a window with all shredding-related options."""
    shredding_window = Toplevel(master)
    shredding_window.title("Shredding Menu")
    shredding_window.geometry("600x300")
    shredding_window.configure(bg="#2f4155")

    Label(shredding_window, text="Shredding Options", font="arial 18 bold", bg="#2f4155",fg="white").pack(pady=20)

    Button(shredding_window, text="Shred a File", command=lambda: open_file_shredder_dialog(shredding_window), width=29).pack(pady=10)
    Button(shredding_window, text="Shred a Directory", command=lambda: open_directory_shredder_dialog(shredding_window), width=29).pack(pady=10)


    Button(shredding_window, text="Close", command=shredding_window.destroy, width=20).pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("File Shredder")
    root.geometry("300x200")

    Label(root, text="Welcome to the File Shredder", font=("Arial", 14)).pack(pady=20)

    Button(root, text="Open Shredding Menu", command=lambda: open_shredding_menu(root), width=20).pack(pady=10)

    root.mainloop()
