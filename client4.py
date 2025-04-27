# client.py
import sys
import socket
import threading
import logging
import os
import ssl
import time
import customtkinter as ctk
from tkinter import messagebox
from ui.login_screen import LoginDialog
from utils.usb_auth import authenticate as usb_authenticate , is_locked_out
from logging_config import setup_logging

logger = setup_logging()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class ChatClient:
    # ------------ constants ------------
    HEARTBEAT_INTERVAL = 20
    RECONNECT_MAX_TRIES = 5
    BACKOFF_BASE_SECS = 2
    MAX_MSG_LEN = 64 * 1024

    # ------------ init / startup ------------
    def __init__(self, master, host, server_port, client_port, position):
        self.master = master
        self.host = host
        self.server_port = int(server_port)
        self.client_port = int(client_port)
        self.position = position

        self.username = ""
        self.password = ""
        self.tls_context = None
        self.client_socket: ssl.SSLSocket | None = None
        self.running = False

        # GUI state
        self.recipient = "Everyone"  # current target

    # ------------ main entry ------------
    def start_chat_client(self):
        # TLS ------------------------------------------------------------
        server_cert = os.path.join(
            os.path.dirname(__file__), "utils", "cert", "server_cert.pem"
        )
        self.tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.tls_context.load_verify_locations(cafile=server_cert)
        self.tls_context.check_hostname = False  # self‑signed CN

        # Login dialog ---------------------------------------------------
        login_dlg = LoginDialog(self.master)
        self.master.wait_window(login_dlg)
        if login_dlg.result is None:
            self.master.quit()
            return
        self.username, self.password = login_dlg.result

        # First connection ----------------------------------------------
        try:
            self._open_socket()
            self._authenticate()
            # ---------- USB second factor ----------
                        # 3 local tries in this session
            for attempt in range(3):
                if is_locked_out(self.username):
                    messagebox.showerror("USB Key", "You are locked out. Try again later.")
                    self.master.quit()
                    return

                if usb_authenticate(self.username):
                    # USB success
                    break
                else:
                    # usb_auth may have shown "Wrong USB" or "Locked out" itself
                    if attempt < 2:
                        messagebox.showerror(
                            "USB Key", f"Wrong USB attempt {attempt+1} of 3.\nTry again."
                        )
                    else:
                        messagebox.showerror("USB Key", "3 wrong attempts. Closing now.")
                        self.master.quit()
                        return
        except Exception as exc:
            logger.error(f"🔴 Unable to connect/authenticate: {exc}")
            messagebox.showerror("Connection Error", str(exc))
            self.master.quit()
            return

        # GUI + background threads --------------------------------------
        self.build_gui()
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()
        threading.Thread(target=self._heartbeat, daemon=True).start()

    # ------------ socket helpers ------------
    def _open_socket(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Optionally: raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(("0.0.0.0", self.client_port))
        self.client_socket = self.tls_context.wrap_socket(raw, server_hostname=self.host)
        self.client_socket.connect((self.host, self.server_port))
        logger.info(f"Connected to {self.host}:{self.server_port}")

    def _authenticate(self):
        creds = f"{self.username}:{self.password}".encode()
        self._send_prefixed(creds)
        resp = self._recv_prefixed().decode()
        if resp != "SUCCESS":
            raise RuntimeError("Invalid username or password")
        logger.info(f"Authenticated as '{self.username}'")

    # ------------ heartbeat ------------
    def _heartbeat(self):
        while self.running:
            try:
                self._send_prefixed(b"PING")
            except Exception:
                break
            time.sleep(self.HEARTBEAT_INTERVAL)

    # ------------ reconnect logic ------------
    def _reconnect_loop(self) -> bool:
        for attempt in range(1, self.RECONNECT_MAX_TRIES + 1):
            wait = self.BACKOFF_BASE_SECS ** (attempt - 1)
            logger.info(f"Reconnect attempt {attempt} in {wait}s …")
            time.sleep(wait)
            try:
                self._open_socket()
                self._authenticate()
                return True
            except Exception as exc:
                logger.warning(f"Reconnect failed: {exc}")
        return False

    # ------------ network I/O helpers ------------
    def _send_prefixed(self, data: bytes):
        self.client_socket.sendall(len(data).to_bytes(4, "big") + data)

    def _recv_prefixed(self) -> bytes:
        hdr = self.client_socket.recv(4)
        if not hdr:
            return b""
        length = int.from_bytes(hdr, "big")
        if length <= 0 or length > self.MAX_MSG_LEN:
            return b""
        return self.client_socket.recv(length)

    # ------------ background receiver ------------
    def receive_messages(self):
        while self.running:
            try:
                data = self._recv_prefixed()
                if not data:
                    raise ConnectionError("EOF")
                msg = data.decode("utf-8")

                # --- handle presence update ----------------------------
                if msg.startswith("USERS "):
                    users = msg.split(" ", 1)[1].split(",")
                    self.update_user_list(users)
                    continue

                # --- normal display ------------------------------------
                self.display_message(msg)

            except Exception as exc:
                logger.warning(f"Connection lost: {exc}")
                self.running = False
                if not messagebox.askyesno(
                    "Disconnected", "Lost connection.\nReconnect?"
                ):
                    self.master.quit()
                    return
                if self._reconnect_loop():
                    logger.info("Reconnected!")
                    self.running = True
                    continue
                else:
                    messagebox.showerror(
                        "Reconnect failed",
                        "Unable to reconnect after several attempts.",
                    )
                    self.master.quit()
                    return

    # ------------- Update & Clickable User List -------------
    def update_user_list(self, users):
        """
        Clears and repopulates the user list in the scrollable frame.
        Each user is clickable to set the chat recipient.
        """
        # Clear all current children from the scrollable frame.
        for widget in self.user_list.winfo_children():
            widget.destroy()

        # Create a dictionary to store label references.
        self.user_labels = {}

        # Combine default "Everyone" with the list of users.
        all_users = ["Everyone"] + users

        # Create a clickable label for each user.
        for user in all_users:
            lbl = ctk.CTkLabel(
                self.user_list,
                text=user,
                fg_color="#212121",  # default background
                text_color="white",
                anchor="w",
                padx=10
            )
            lbl.pack(pady=2, padx=2, anchor="w", fill="x")
            # Bind left-click event to update the selected recipient.
            lbl.bind("<Button-1>", lambda event, usr=user: self.set_recipient(usr))
            self.user_labels[user] = lbl

        # Restore or set default recipient.
        if self.recipient not in all_users:
            self.set_recipient("Everyone")
        else:
            self.set_recipient(self.recipient)

    def set_recipient(self, user: str):
        """
        Sets the current message recipient and highlights the corresponding label.
        """
        # Un-highlight the previously selected recipient.
        if hasattr(self, "user_labels") and self.recipient in self.user_labels:
            self.user_labels[self.recipient].configure(fg_color="#212121")
        # Update recipient.
        self.recipient = user
        # Highlight the newly selected recipient.
        if hasattr(self, "user_labels") and user in self.user_labels:
            self.user_labels[user].configure(fg_color="#2A2D2E")

    # ------------ GUI ------------
    def build_gui(self):
        # Increase overall width to fit sidebar on the left.
        self.master.title(f"Secure Chat – {self.username}")
        self.master.geometry("800x680")
        self.master.configure(fg_color="#1a1a1a")
        self.master.geometry(f"+{self.position[0]}+{self.position[1]}")

        # Configure grid: column 0 for the sidebar, column 1 for the chat area.
        self.master.grid_columnconfigure(0, weight=0)  # sidebar is fixed size
        self.master.grid_columnconfigure(1, weight=1)  # chat area expands
        # Row 1 (chat frame) should expand vertically.
        self.master.grid_rowconfigure(1, weight=1)

        # ---- Sidebar (Users list) -------------------------------
        self.sidebar = ctk.CTkFrame(
            self.master,
            corner_radius=0,
            width=250,
            height=300,
            fg_color="#212121"
        )
        # Place the sidebar in column 0, spanning all rows used by the chat area.
        self.sidebar.grid(row=0, column=0, rowspan=3, sticky="ns", padx=(10, 0), pady=10)

        self.user_list = ctk.CTkScrollableFrame(
            master=self.sidebar,
            label_text="Users",
            width=210,
            height=159,
            fg_color="#212121",
            scrollbar_button_hover_color="#5F87AF"
        )
        self.user_list.pack(pady=3, padx=3, anchor="center")

        # ---- Chat Area ------------------------------------------
        # Header (displayed at the top of the chat area)
        header = ctk.CTkLabel(
            self.master,
            text=f"Secure Chat – {self.username}",
            font=("Courier New", 20, "bold"),
            fg_color="#1a1a1a",
            text_color="#5F87AF"
        )
        header.grid(row=0, column=1, pady=6, padx=10, sticky="ew")

        # Chat frame to display conversation text.
        frame = ctk.CTkFrame(
            self.master,
            fg_color="#3A506B",
            corner_radius=0,
            border_width=1
        )
        frame.grid(row=1, column=1, padx=10, pady=6, sticky="nsew")

        self.textCons = ctk.CTkTextbox(
            frame,
            fg_color="#1a1a1a",
            text_color="#00FF00",
            font=("Courier New", 18),
            padx=5,
            pady=5
        )
        self.textCons.pack(fill="both", expand=True, padx=4, pady=4)
        self.textCons.configure(state="disabled")

        # ---- Message Input Area ---------------------------------
        # Create a dedicated frame for input so the entry and button remain together.
        input_frame = ctk.CTkFrame(self.master, fg_color="#1a1a1a")
        input_frame.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)

        self.entryMsg = ctk.CTkEntry(
            input_frame,
            fg_color="#262626",
            text_color="#00FF00",
            font=("Helvetica", 18)
        )
        self.entryMsg.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.entryMsg.bind("<Return>", self.send_message)
        self.entryMsg.focus()

        send_btn = ctk.CTkButton(
            input_frame,
            text="Send",
            font=("Courier New", 12, "bold"),
            fg_color="#8A9BA8",
            text_color="#1a1a1a",
            command=self.send_message
        )
        send_btn.grid(row=0, column=1, padx=5, pady=5)

    def _on_recipient_change(self, choice):
        self.recipient = choice

    # ------------ chat actions ------------
    def send_message(self, _event=None):
        msg = self.entryMsg.get().strip()
        if not msg:
            return
        try:
            # private or broadcast?
            if self.recipient != "Everyone":
                wire = f"TO {self.recipient} {msg}".encode()
                shown = f"You ➜ {self.recipient}: {msg}"
            else:
                wire = f"{self.username}:{msg}".encode()
                shown = f"You: {msg}"

            self._send_prefixed(wire)
            self.display_message(shown)
            self.entryMsg.delete(0, "end")
        except Exception as exc:
            logger.error(f"🔴 Send failed: {exc}")
            messagebox.showerror("Send Error", str(exc))
            self.master.quit()

    def display_message(self, text: str):
        self.textCons.configure(state="normal")
        self.textCons.insert("end", text + "\n")
        self.textCons.configure(state="disabled")
        self.textCons.yview("end")

    # ------------ cleanup ------------
    def close_connection(self):
        logger.info(f"Client '{self.username}' closing.")
        self.running = False
        try:
            if self.client_socket:
                self._send_prefixed(f"{self.username}:<left the chat>".encode())
                self.client_socket.close()
        except Exception:
            pass
        self.master.quit()


# ------------ entrypoint ------------
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client.py <server_ip> <server_port> <client_port>")
        sys.exit(1)

    host, srv_port, cli_port = sys.argv[1:]
    root = ctk.CTk()
    client = ChatClient(root, host, srv_port, cli_port, position=(100, 100))
    client.start_chat_client()
    root.protocol("WM_DELETE_WINDOW", client.close_connection)
    root.mainloop()
