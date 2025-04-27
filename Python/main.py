#!/usr/bin/env python
"""
main.py – launcher for three Secure-Chat clients (no server)

• lets you type the server’s port and three distinct local client ports
• validates port range 1024-65535
• spawns the three client scripts as subprocesses
"""

import tkinter as tk
from tkinter import Label, Entry, Button, messagebox
import subprocess, threading, os, sys
from typing import List

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from logging_config import setup_logging

logger = setup_logging()


# ── helpers ──────────────────────────────────────────────────────────
def sanitize(inp: str) -> str:
    inp = inp.strip()
    return inp if inp.isdigit() else ""


def valid(port_str: str) -> bool:
    try:
        p = int(port_str)
        return 1024 <= p <= 65_535
    except ValueError:
        return False


# ── GUI class ────────────────────────────────────────────────────────
class ConfigWindow:
    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("Secure Chat – Client Launcher")
        self.master.geometry("450x540+760+340")
        self.master.configure(bg="#1a1a1a")

        Label(master, text="Secure Chat – Launch Clients",
              font=("Courier New", 18, "bold"),
              bg="#1a1a1a", fg="#00FF00").pack(pady=20)

        self.entries: List[Entry] = []
        for label_txt, default in [
            ("Server Port:", "4444"),
            ("Client 1 Port:", "12346"),
            ("Client 2 Port:", "12347"),
            ("Client 3 Port:", "12348"),
        ]:
            Label(master, text=label_txt, font=("Courier New", 12, "bold"),
                  bg="#1a1a1a", fg="#FFFFFF").pack(pady=5)
            e = Entry(master, bg="#333333", fg="#FFFFFF",
                      font=("Courier New", 12), insertbackground="#FFFFFF")
            e.pack(pady=5);  e.insert(0, default)
            self.entries.append(e)

        Button(master, text="Start Clients", font=("Courier New", 12, "bold"),
               bg="#00FF00", fg="#1a1a1a",
               command=self.start_clients).pack(pady=25)

    # ── button callback ────────────────────────────────────────────
    def start_clients(self):
        server_p, c1_p, c2_p, c3_p = [sanitize(e.get()) for e in self.entries]

        # any blank or non-numeric ?
        if not all([server_p, c1_p, c2_p, c3_p]):
            messagebox.showerror("Input error", "All ports must be numeric.")
            return

        bad = [name for name, p in [("Server", server_p),
                                    ("Client 1", c1_p),
                                    ("Client 2", c2_p),
                                    ("Client 3", c3_p)] if not valid(p)]
        if bad:
            messagebox.showerror("Input error", f"Invalid port(s): {', '.join(bad)}")
            return

        logger.info("Launching three clients …")
        base = os.path.abspath(os.path.dirname(__file__))
        for n, cli_port in enumerate([c1_p, c2_p, c3_p], start=1):
            path = os.path.join(base, f"secure_chat_client{n}.py")
            if not os.path.exists(path):
                messagebox.showerror("File missing", f"Cannot find {path}")
                return
            args = ["python", path, "localhost", server_p, cli_port]
            logger.debug("Exec: %s", " ".join(args))
            threading.Thread(target=subprocess.Popen, args=(args,), daemon=True).start()

        self.master.destroy()


# ── entrypoint ───────────────────────────────────────────────────────
if __name__ == "__main__":
    logger.debug("Launcher started")
    root = tk.Tk()
    ConfigWindow(root)
    root.mainloop()
