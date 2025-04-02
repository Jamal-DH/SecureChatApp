# glitch.py

import tkinter as tk
from PIL import Image, ImageDraw, ImageFont, ImageChops, ImageTk
import random

def run_glitch_effect_tkinter():
    # Create a new full-screen Tkinter window
    glitch_window = tk.Toplevel()
    glitch_window.attributes('-fullscreen', True)
    glitch_window.attributes('-topmost', True)
    glitch_window.configure(background='black')

    # Get the display's width and height
    width = glitch_window.winfo_screenwidth()
    height = glitch_window.winfo_screenheight()

    # Create a canvas to display the glitch effect
    canvas = tk.Canvas(glitch_window, width=width, height=height, highlightthickness=0)
    canvas.pack()

    # Glitch characters to use
    glitch_chars = ['Ѭ', '҂', '█▀█\n█▄█', '∭', '☠☠☠\n☠☠☠', '∬', '∰', '⛢', '⎯⎯⎯⎯⎯\n⎯⎯⎯⎯⎯', '𝔄', '𝔅', '𝔇', '⬢', '⬣',
                    'ᚠ', '⧈⧉⧈\n⧉⧈⧉', 'ᚢ', '⧈⧉⧈', 'ᚦ', '▓▓▓\n▓▓▓', 'ᚩ', '█▓▒░\n░▒▓█']

    # Create a function to generate glitchy text
    def create_glitch_text(original_text, glitch_probability=0.9):
        glitched_text = ''
        for char in original_text:
            if char != ' ' and random.random() < glitch_probability:
                glitched_text += random.choice(glitch_chars)
            else:
                glitched_text += char
        return glitched_text

    # Create a function to generate the base image
    def create_base_image(text):
        image = Image.new('RGB', (width, height), 'black')
        draw = ImageDraw.Draw(image)

        # Add hacker-themed text
        font_size = 60
        try:
            # Replace 'arial.ttf' with the path to a font file on your system
            font = ImageFont.truetype('arial.ttf', font_size)
        except IOError:
            font = ImageFont.load_default()

        # Calculate text size
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        # Center the text
        text_x = (width - text_width) // 2
        text_y = (height - text_height) // 2

        # Draw the text
        draw.text((text_x, text_y), text, font=font, fill='Red')
        return image

    # Function to apply advanced glitch effects
    def glitch_image_real_time(img):
        num_glitches = random.randint(1, 3)
        for _ in range(num_glitches):
            effect = random.choice(['shift_band', 'color_channel_shift', 'scanlines', 'noise'])
            if effect == 'shift_band':
                # Randomly select the glitch parameters
                glitch_height = random.randint(5, 30)
                glitch_start = random.randint(0, img.height - glitch_height)
                glitch_shift = random.randint(-20, 20)

                # Crop a horizontal band from the image
                box = (0, glitch_start, img.width, glitch_start + glitch_height)
                band = img.crop(box)

                # Shift the band horizontally
                img.paste(band, (glitch_shift, glitch_start))
            elif effect == 'color_channel_shift':
                # Split into R, G, B channels
                r, g, b = img.split()
                # Shift one channel
                shift = random.randint(-5, 5)
                channel_to_shift = random.choice(['R', 'G', 'B'])
                if channel_to_shift == 'R':
                    r = ImageChops.offset(r, shift, 0)
                elif channel_to_shift == 'G':
                    g = ImageChops.offset(g, shift, 0)
                elif channel_to_shift == 'B':
                    b = ImageChops.offset(b, shift, 0)
                # Merge back
                img = Image.merge('RGB', (r, g, b))
            elif effect == 'scanlines':
                draw = ImageDraw.Draw(img)
                line_spacing = random.randint(3, 10)
                line_color = (0, 0, 0)
                for y in range(0, img.height, line_spacing):
                    draw.line([(0, y), (img.width, y)], fill=line_color)
            elif effect == 'noise':
                # Add random noise
                pixels = img.load()
                for _ in range(img.width * img.height // 100):
                    x = random.randint(0, img.width - 1)
                    y = random.randint(0, img.height - 1)
                    pixels[x, y] = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        return img

    # Variables to control glitch timing and duration
    text_glitch_cooldown = 0
    text_glitch_duration = 0
    image_glitch_cooldown = 0
    image_glitch_duration = 0

    base_text = "ACCESS DENIED"

    # Create the base image once
    base_image = create_base_image(base_text)
    current_image = base_image.copy()
    glitched_text_image = None

    # Update the canvas with the glitch effect
    def update_canvas():
        # Check if the canvas widget still exists
        if not canvas.winfo_exists():
            return  # Stop updating if the canvas has been destroyed

        nonlocal text_glitch_cooldown, text_glitch_duration, image_glitch_cooldown, image_glitch_duration
        nonlocal current_image, glitched_text_image

        # Text glitch handling
        if text_glitch_cooldown <= 0 and text_glitch_duration <= 0:
            if random.random() < 0.9:
                text_glitch_duration = random.randint(10, 30)
                text_glitch_cooldown = random.randint(200, 400)
                # Create glitchy text image
                glitched_text = create_glitch_text(base_text, glitch_probability=0.1)
                glitched_text_image = create_base_image(glitched_text)
        else:
            if text_glitch_duration > 0:
                text_glitch_duration -= 1
                current_image = glitched_text_image
            else:
                text_glitch_cooldown -= 1
                current_image = base_image

        # Image glitch handling
        display_image = current_image.copy()

        if image_glitch_cooldown <= 0 and image_glitch_duration <= 0:
            if random.random() < 0.08:
                image_glitch_duration = random.randint(5, 15)
                image_glitch_cooldown = random.randint(60, 180)
        else:
            if image_glitch_duration > 0:
                # Apply glitch effect
                display_image = glitch_image_real_time(display_image)
                image_glitch_duration -= 1
            else:
                image_glitch_cooldown -= 1

        # Convert the PIL image to a PhotoImage
        photo = ImageTk.PhotoImage(display_image)
        canvas.create_image(0, 0, anchor=tk.NW, image=photo)
        canvas.image = photo  # Keep a reference

        # Update the canvas every 50 milliseconds
        canvas.after(10, update_canvas)

    # Start updating the canvas
    update_canvas()

    # Close the window after 25 seconds using 'after' instead of threading
    glitch_window.after(25000, glitch_window.destroy)

    # Start the glitch window's mainloop
    glitch_window.mainloop()
