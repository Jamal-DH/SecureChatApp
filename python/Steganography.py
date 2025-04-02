import customtkinter as ctk
from tkinter import filedialog, messagebox
from customtkinter import CTkImage
import os
from PIL import Image, ImageTk
from stegano import lsb
from cryptography.fernet import Fernet
import logging

# Configure logging
def setup_logging():
    home_dir = os.path.expanduser("~")
    log_dir = os.path.join(home_dir, "SteganographyApp_Logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "app.log")
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s:%(levelname)s:%(message)s'
    )

class SteganographyApp:
    """
    A graphical user interface (GUI) application for hiding and revealing messages within images
    using the Least Significant Bit (LSB) steganography technique. Optionally, messages can be
    encrypted before being hidden using Fernet symmetric encryption.
    """
    def __init__(self, root):
        """
        Initializes the SteganographyApp with the main window and sets up the GUI components.
        
        Args:
            root (CTk): The main CustomTkinter window instance.
        """
        setup_logging()
        self.root = root
        self.root.title("Advanced Steganography")                # Set the window title
        self.root.geometry("800x550+150+100")                     # Set window size and position
        self.root.resizable(False, False)                         # Disable window resizing
        self.root.configure(fg_color="#2f4155")                   # Set the background color using CustomTkinter

        # Initialize global variables
        self.hidden_image = None  # Stores the image with hidden data
        self.key = None           # Stores the encryption key (if used)

        # Setup the GUI layout and widgets
        self.setup_gui()

    def setup_gui(self):
        """
        Sets up the GUI layout by creating and placing frames, labels, textboxes, and buttons.
        """
        # LOGO LABEL
        self.logo_label = ctk.CTkLabel(
            self.root,
            text="Advanced Steganography LSB Algorithm",
            font=ctk.CTkFont(size=25, weight="bold"),
            fg_color="#2f4155",
            text_color="white"
        )
        self.logo_label.pack(pady=20)  # Place the logo label with vertical padding

        # FIRST FRAME: Image Display Area
        self.f1 = ctk.CTkFrame(
            self.root,
            fg_color="black",
            corner_radius=10,
            width=390,
            height=280
        )
        self.f1.place(x=10, y=80)  # Position the frame within the window

        # Label within the first frame to display the selected image
        self.lb = ctk.CTkLabel(self.f1, text="")
        self.lb.place(x=40, y=10)  # Position the image label within the frame

        # SECOND FRAME: Text Box for Message Input
        self.f2 = ctk.CTkFrame(
            self.root,
            fg_color="#2f4155",
            bg_color="white",
            corner_radius=10,
            width=390,
            height=280
        )
        self.f2.place(x=400, y=80)  # Position the frame within the window

        # Textbox within the second frame for user to input the message to hide/reveal
        self.text1 = ctk.CTkTextbox(
            self.f2,
            font=("Roboto", 20),
            wrap="word",
            width=390,
            height=280
        )
        self.text1.place(x=0, y=0)  # Position the textbox within the frame

        # THIRD FRAME: Buttons for Image Handling (Open and Save)
        self.f3 = ctk.CTkFrame(
            self.root,
            fg_color="#263445",
            corner_radius=10,
            width=390,
            height=160
        )
        self.f3.place(x=10, y=370)  # Position the frame within the window

        # "Open Image" button to select an image file
        self.open_button = ctk.CTkButton(
            self.f3,
            text="Open Image",
            command=self.showimage,
            width=140,
            height=45
        )
        self.open_button.place(x=20, y=80)  # Position the button within the frame

        # "Save Image" button to save the image with hidden data
        self.save_button = ctk.CTkButton(
            self.f3,
            text="Save Image",
            command=self.save_image,
            width=140,
            height=45
        )
        self.save_button.place(x=180, y=80)  # Position the button within the frame

        # Label to display instructions or status related to image selection
        self.img_label = ctk.CTkLabel(
            self.f3,
            text="Picture, Image, Photo File",
            fg_color="#263445",
            text_color="red"
        )
        self.img_label.place(x=20, y=22)  # Position the label within the frame

        # FOURTH FRAME: Buttons for Hiding and Showing Data
        self.f4 = ctk.CTkFrame(
            self.root,
            fg_color="#263445",
            corner_radius=10,
            width=390,
            height=160
        )
        self.f4.place(x=400, y=370)  # Position the frame within the window

        # "Hide Data" button to embed the message into the image
        self.hide_button = ctk.CTkButton(
            self.f4,
            text="Hide Data",
            command=self.hide_data,
            width=140,
            height=45
        )
        self.hide_button.place(x=30, y=80)  # Position the button within the frame

        # "Show Data" button to extract the message from the image
        self.show_button = ctk.CTkButton(
            self.f4,
            text="Show Data",
            command=self.show_data,
            width=140,
            height=45
        )
        self.show_button.place(x=190, y=80)  # Position the button within the frame

    def showimage(self):
        """
        Opens a file dialog for the user to select an image file.
        Displays the selected image within the GUI.
        """
        try:
            filename = filedialog.askopenfilename(
                initialdir=os.getcwd(),
                title="Select Image File",
                filetypes=(
                    ("PNG file", "*.png"),
                    ("JPG file", "*.jpg"),
                    ("All Files", "*.*")
                )
            )
            if filename:
                img = Image.open(filename)          # Open the selected image
                img.thumbnail((250, 250))           # Resize the image to fit within the display area
                ctk_img = CTkImage(light_image=img, size=(250, 250))  # Create a CTkImage for CustomTkinter

                self.lb.configure(image=ctk_img)    # Display the image in the label
                self.lb.image = ctk_img             # Keep a reference to prevent garbage collection
                self.filename = filename            # Store the filename for later use
                logging.info(f"Opened image: {filename}")
        except Exception as e:
            # Show an error message if the image fails to open
            messagebox.showerror("Error", f"Failed to open image: {str(e)}")
            logging.error(f"Failed to open image: {str(e)}")

    def hide_data(self):
        """
        Hides the user-provided message within the selected image using LSB steganography.
        Optionally encrypts the message before embedding if an encryption key is loaded.
        """
        try:
            if not hasattr(self, 'filename') or not self.filename:
                messagebox.showwarning("Warning", "No image selected. Please open an image first.")
                return

            message = self.text1.get("1.0", "end-1c").strip()  # Retrieve the message from the textbox
            if not message:
                # Warn the user if the message is empty
                messagebox.showwarning("Warning", "Message to hide cannot be empty.")
                return

            # Encrypt the message if an encryption key is loaded
            if self.key:
                cipher_suite = Fernet(self.key)
                message = cipher_suite.encrypt(message.encode()).decode()

            # Hide the (encrypted) message in the selected image
            self.hidden_image = lsb.hide(self.filename, message)
            messagebox.showinfo("Success", "Data hidden successfully.")  # Inform the user of success
            logging.info(f"Data hidden in image: {self.filename}")
        except Exception as e:
            # Show an error message if hiding data fails
            messagebox.showerror("Error", f"Failed to hide data: {str(e)}")
            logging.error(f"Failed to hide data: {str(e)}")

    def show_data(self):
        """
        Reveals the hidden message from the selected image using LSB steganography.
        Decrypts the message if an encryption key is loaded.
        """
        try:
            if not hasattr(self, 'filename') or not self.filename:
                messagebox.showwarning("Warning", "No image selected. Please open an image first.")
                return

            clear_msg = lsb.reveal(self.filename)  # Extract the hidden message from the image
            if self.key and clear_msg:
                # Decrypt the message if an encryption key is loaded
                cipher_suite = Fernet(self.key)
                clear_msg = cipher_suite.decrypt(clear_msg.encode()).decode()

            # Display the revealed message in the textbox
            self.text1.delete("1.0", "end")  # Clear the textbox
            self.text1.insert("end", clear_msg)  # Insert the revealed message
            messagebox.showinfo("Success", "Data revealed successfully.")
            logging.info(f"Data revealed from image: {self.filename}")
        except Exception as e:
            # Show an error message if revealing data fails
            messagebox.showerror("Error", f"Failed to reveal data: {str(e)}")
            logging.error(f"Failed to reveal data: {str(e)}")

    def save_image(self):
        """
        Saves the image with the hidden message to a user-specified location.
        Clears the display after saving.
        """
        try:
            if self.hidden_image:
                # Open a file dialog to specify the save location
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".png",
                    filetypes=[("PNG file", "*.png")],
                    title="Save Image As"
                )
                if save_path:
                    self.hidden_image.save(save_path)  # Save the image with hidden data
                    messagebox.showinfo("Success", f"Image saved successfully as {save_path}")
                    logging.info(f"Image saved with hidden data: {save_path}")
                    self.clear_display()  # Clear the display after saving
                else:
                    # Warn the user if the save operation is cancelled
                    messagebox.showwarning("Warning", "Save operation cancelled.")
            else:
                # Warn the user if there is no hidden image to save
                messagebox.showwarning("Warning", "No hidden image to save.")
        except Exception as e:
            # Show an error message if saving the image fails
            messagebox.showerror("Error", f"Failed to save image: {str(e)}")
            logging.error(f"Failed to save image: {str(e)}")

    def generate_key(self):
        """
        Generates a new encryption key using Fernet and saves it to a file named 'secret.key'.
        """
        try:
            self.key = Fernet.generate_key()  # Generate a new Fernet encryption key
            home_dir = os.path.expanduser("~")
            key_dir = os.path.join(home_dir, "SteganographyApp_Keys")
            os.makedirs(key_dir, exist_ok=True)  # Create directories if they don't exist
            key_path = os.path.join(key_dir, "secret.key")

            with open(key_path, "wb") as key_file:
                key_file.write(self.key)       # Save the key to a file
            messagebox.showinfo("Info", f"Encryption key generated and saved as {key_path}")
            logging.info(f"Encryption key generated and saved at {key_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate/save key: {str(e)}")
            logging.error(f"Failed to generate/save key: {str(e)}")

    def load_key(self):
        """
        Loads an existing encryption key from the 'secret.key' file.
        """
        try:
            home_dir = os.path.expanduser("~")
            key_path = os.path.join(home_dir, "SteganographyApp_Keys", "secret.key")
            with open(key_path, "rb") as key_file:
                self.key = key_file.read()  # Read the encryption key from the file
            messagebox.showinfo("Info", f"Encryption key loaded successfully from {key_path}.")
            logging.info(f"Encryption key loaded from {key_path}")
        except FileNotFoundError:
            response = messagebox.askyesno("Key Not Found", 
                                           f"'secret.key' not found at {key_path}. Would you like to generate a new key?")
            if response:
                self.generate_key()
        except Exception as e:
            # Show an error message if loading the key fails
            messagebox.showerror("Error", f"Failed to load encryption key: {str(e)}")
            logging.error(f"Failed to load encryption key: {str(e)}")

    def clear_display(self):
        """
        Clears the image display and the message textbox.
        Resets the hidden image variable.
        """
        self.lb.configure(image=None)   # Properly remove the image from the label
        self.lb.image = None            # Remove the reference to the image
        self.text1.delete("1.0", "end")  # Clear the textbox
        self.hidden_image = None        # Reset the hidden_image variable
        logging.info("Display cleared.")

if __name__ == "__main__":
    """
    Entry point for the SteganographyApp.
    Sets the appearance mode, initializes the main window, and starts the GUI event loop.
    """
    setup_logging()
    ctk.set_appearance_mode("dark")  # Set the theme to dark (options: "light", "dark", "system")
    root = ctk.CTk()                  # Initialize the main CustomTkinter window
    app = SteganographyApp(root)      # Create an instance of the SteganographyApp
    root.mainloop()                   # Start the GUI event loop
