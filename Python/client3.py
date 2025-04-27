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
        self.recipient = "Everyone"          # current target

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
                    menu_vals = ["Everyone"] + users
                    # keep selection if still valid
                    sel = self.recipient if self.recipient in menu_vals else "Everyone"
                    self.user_list.configure(values=menu_vals)
                    self.user_list.set(sel)
                    self.recipient = sel
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

    # ------------ GUI ------------
    def build_gui(self):
        self.master.title(f"Secure Chat – {self.username}")
        self.master.geometry("600x680")
        self.master.configure(fg_color="#1a1a1a")
        self.master.geometry(f"+{self.position[0]}+{self.position[1]}")

        header = ctk.CTkLabel(
            self.master,
            text=f"Secure Chat – {self.username}",
            font=("Courier New", 20, "bold"),
            fg_color="#1a1a1a",
            text_color="#5F87AF",
        )
        header.grid(row=0, column=0, columnspan=2, pady=6)

        frame = ctk.CTkFrame(
            self.master, fg_color="#3A506B", corner_radius=0, border_width=1
        )
        frame.grid(row=1, column=0, columnspan=2, padx=6, pady=6, sticky="nsew")

        self.textCons = ctk.CTkTextbox(
            frame,
            fg_color="#1a1a1a",
            text_color="#00FF00",
            font=("Courier New", 18),
            padx=5,
            pady=5,
        )
        self.textCons.pack(fill="both", expand=True, padx=4, pady=4)
        self.textCons.configure(state="disabled")

        # ---- message entry + send ------------------------------------
        self.entryMsg = ctk.CTkEntry(
            self.master, fg_color="#262626", text_color="#00FF00", font=("Helvetica", 18)
        )
        self.entryMsg.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.entryMsg.bind("<Return>", self.send_message)
        self.entryMsg.focus()

        send_btn = ctk.CTkButton(
            self.master,
            text="Send",
            font=("Courier New", 12, "bold"),
            fg_color="#8A9BA8",
            text_color="#1a1a1a",
            command=self.send_message,
        )
        send_btn.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        # ---- user list / recipient selector --------------------------
        self.user_list = ctk.CTkOptionMenu(
            self.master, values=["Everyone"], command=self._on_recipient_change
        )
        self.user_list.grid(row=3, column=0, columnspan=2, pady=(0, 10), sticky="ew")

        # layout weights
        self.master.grid_rowconfigure(1, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

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
