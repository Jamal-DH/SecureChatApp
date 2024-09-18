import customtkinter as ctk
from tkinter import filedialog, messagebox
from customtkinter import CTkImage
import os
from PIL import Image, ImageTk
from stegano import lsb
from cryptography.fernet import Fernet


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Steganography")
        self.root.geometry("800x550+150+100")
        self.root.resizable(False, False)
        self.root.configure(fg_color="#2f4155")  # CustomTkinter color configuration

        # Global variables
        self.hidden_image = None
        self.key = None

        # GUI Setup
        self.setup_gui()

    def setup_gui(self):
        # LOGO
        self.logo_label = ctk.CTkLabel(self.root, text="Advanced Steganography LSB Algorithm",
                                       font=ctk.CTkFont(size=25, weight="bold"),
                                       fg_color="#2f4155", text_color="white")
        self.logo_label.pack(pady=20)

        # First Frame (Image Display)
        self.f1 = ctk.CTkFrame(self.root, fg_color="black", corner_radius=10, width=390, height=280)
        self.f1.place(x=10, y=80)

        self.lb = ctk.CTkLabel(self.f1, text="")
        self.lb.place(x=40, y=10)

        # Second Frame (Text Box for Message)
        self.f2 = ctk.CTkFrame(self.root, fg_color="#2f4155",bg_color="white", corner_radius=10, width=390, height=280)
        self.f2.place(x=400, y=80)

        self.text1 = ctk.CTkTextbox(self.f2, font=("Roboto", 20), wrap="word", width=390, height=280)
        self.text1.place(x=0, y=0)

        # Third Frame (Buttons for Image Handling)
        self.f3 = ctk.CTkFrame(self.root, fg_color="#263445", corner_radius=10, width=390, height=160)
        self.f3.place(x=10, y=370)

        self.open_button = ctk.CTkButton(self.f3, text="Open Image", command=self.showimage,width=140, height=45)
        self.open_button.place(x=20, y=80)

        self.save_button = ctk.CTkButton(self.f3, text="Save Image", command=self.save_image,width=140, height=45)
        self.save_button.place(x=180, y=80)

        self.img_label = ctk.CTkLabel(self.f3, text="Picture, Image, Photo File", fg_color="#263445", text_color="red")
        self.img_label.place(x=20, y=22)

        # Fourth Frame (Buttons for Hiding/Showing Data)
        self.f4 = ctk.CTkFrame(self.root, fg_color="#263445", corner_radius=10, width=390, height=160)
        self.f4.place(x=400, y=370)

        self.hide_button = ctk.CTkButton(self.f4, text="Hide Data", command=self.hide_data,width=140, height=45)
        self.hide_button.place(x=30, y=80)

        self.show_button = ctk.CTkButton(self.f4, text="Show Data", command=self.show_data,width=140, height=45)
        self.show_button.place(x=190, y=80)

    from PIL import Image
    from customtkinter import CTkImage  # Import CTkImage



    def showimage(self):
            try:
                filename = filedialog.askopenfilename(initialdir=os.getcwd(),
                                                      title="Select Image File",
                                                      filetypes=(("PNG file", "*.png"), ("JPG file", "*.jpg"),
                                                                 ("All Files", "*.*")))
                if filename:
                    img = Image.open(filename)
                    img.thumbnail((250, 250))  # Resize the image
                    ctk_img = CTkImage(light_image=img, size=(250, 250))  # Create a CTkImage

                    self.lb.configure(image=ctk_img)
                    self.lb.image = ctk_img  # Keep a reference to prevent garbage collection
                    self.filename = filename
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open image: {str(e)}")

    def hide_data(self):
        try:
            message = self.text1.get("1.0", "end-1c").strip()
            if not message:
                messagebox.showwarning("Warning", "Message to hide cannot be empty.")
                return

            # Encrypt the message (optional)
            if self.key:
                cipher_suite = Fernet(self.key)
                message = cipher_suite.encrypt(message.encode()).decode()

            self.hidden_image = lsb.hide(self.filename, message)
            messagebox.showinfo("Success", "Data hidden successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide data: {str(e)}")

    def show_data(self):
        try:
            clear_msg = lsb.reveal(self.filename)
            if self.key:
                cipher_suite = Fernet(self.key)
                clear_msg = cipher_suite.decrypt(clear_msg.encode()).decode()

            self.text1.delete("1.0", "end")
            self.text1.insert("end", clear_msg)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reveal data: {str(e)}")

    def save_image(self):
        try:
            if self.hidden_image:
                save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                         filetypes=[("PNG file", "*.png")],
                                                         title="Save Image As")
                if save_path:
                    self.hidden_image.save(save_path)
                    messagebox.showinfo("Success", f"Image saved successfully as {save_path}")
                    self.clear_display()
                else:
                    messagebox.showwarning("Warning", "Save operation cancelled.")
            else:
                messagebox.showwarning("Warning", "No hidden image to save.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save image: {str(e)}")

    def generate_key(self):
        self.key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(self.key)
        messagebox.showinfo("Info", "Encryption key generated and saved as secret.key")

    def load_key(self):
        try:
            with open("secret.key", "rb") as key_file:
                self.key = key_file.read()
            messagebox.showinfo("Info", "Encryption key loaded successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load encryption key: {str(e)}")

    def clear_display(self):
        # Clear image and text area after saving or loading
        self.lb.configure(image='')
        self.lb.image = None
        self.text1.delete("1.0", "end")
        self.hidden_image = None


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")  # You can set this to "light" or "dark" for theme
    root = ctk.CTk()  # Use CTk instead of Tk for CustomTkinter
    app = SteganographyApp(root)
    root.mainloop()
