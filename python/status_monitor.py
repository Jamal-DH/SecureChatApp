# status_monitor.py

import asyncio
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime

import customtkinter as ctk
import matplotlib.pyplot as plt
import psutil
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from ping3 import ping
from plyer import notification
from tkinter import messagebox, scrolledtext

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('status_monitor.log'),
        logging.StreamHandler()
    ]
)

# Configure CustomTkinter appearance
ctk.set_appearance_mode("dark")  # Modes: system (default), light, dark
ctk.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

# Constants
DATA_LOG_FILE = "system_network_log.json"
REFRESH_INTERVAL = 5  # in seconds


class StatusMonitor:
    """
    Monitors system and network metrics and notifies observers.
    """

    def __init__(self):
        """
        Initializes the StatusMonitor.
        """
        self.observers = []
        self.alerts = []
        self.lock = threading.Lock()
        self.running = False
        self.thread = None

        self.thresholds = {
            'cpu_usage': 90,           # in percent
            'memory_usage': 90,        # in percent
            'disk_usage': 90,          # in percent
            'bandwidth_usage': 1000,   # in Mbps
            'latency': 100,            # in ms
            'packet_loss': 5           # in percent
        }

        self.network_stats = {
            'previous_bytes_sent': psutil.net_io_counters().bytes_sent,
            'previous_bytes_recv': psutil.net_io_counters().bytes_recv,
            'bandwidth_history': [],
            'time_history': []
        }

        self.system_health = {}
        self.network_information = {}
        self.connection_status = {}

        self.data_log = {
            'system_health': [],
            'network_information': [],
            'alerts': []
        }

        self.load_data_log()

    def register_observer(self, observer):
        """
        Registers an observer to receive updates.
        """
        self.observers.append(observer)

    def unregister_observer(self, observer):
        """
        Unregisters an observer.
        """
        self.observers.remove(observer)

    def notify_observers(self):
        """
        Notifies all registered observers with the latest data.
        """
        for observer in self.observers:
            observer.update(self.get_status_data())

    def load_data_log(self):
        """
        Load historical data from a log file.
        """
        if os.path.exists(DATA_LOG_FILE):
            try:
                with open(DATA_LOG_FILE, 'r') as f:
                    self.data_log = json.load(f)
            except json.JSONDecodeError:
                logging.warning("Data log file is corrupted. Starting fresh.")
                self.data_log = {
                    'system_health': [],
                    'network_information': [],
                    'alerts': []
                }
        else:
            self.data_log = {
                'system_health': [],
                'network_information': [],
                'alerts': []
            }

    def save_data_log(self):
        """
        Save historical data to a log file.
        """
        with open(DATA_LOG_FILE, 'w') as f:
            json.dump(self.data_log, f, indent=4)

    def start(self):
        """
        Starts the monitoring in a separate thread.
        """
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.monitor, daemon=True)
            self.thread.start()
            logging.info("StatusMonitor started.")

    def stop(self):
        """
        Stops the monitoring.
        """
        if self.running:
            self.running = False
            if self.thread is not None:
                self.thread.join()
            self.save_data_log()
            logging.info("StatusMonitor stopped.")

    def monitor(self):
        """
        Continuously monitor system and network metrics.
        """
        while self.running:
            self.collect_metrics()
            self.notify_observers()
            time.sleep(REFRESH_INTERVAL)

    def collect_metrics(self):
        """
        Collect all necessary metrics.
        """
        try:
            self.collect_system_health()
            self.collect_network_information()
            self.collect_connection_status()
            self.log_data()
        except Exception as e:
            logging.exception("Error collecting metrics.")

    def collect_system_health(self):
        """
        Collect CPU, Memory, and Disk usage.
        """
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        disk = psutil.disk_usage('/')
        disk_usage = disk.percent

        # Check thresholds and trigger alerts if necessary
        self.check_threshold('CPU Usage', cpu_usage, self.thresholds['cpu_usage'])
        self.check_threshold('Memory Usage', memory_usage, self.thresholds['memory_usage'])
        self.check_threshold('Disk Usage', disk_usage, self.thresholds['disk_usage'])

        # Update system health data
        self.system_health = {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }

    def collect_network_information(self):
        """
        Collect Bandwidth usage, Latency, and Packet Loss.
        """
        # Bandwidth Usage Calculation
        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent
        bytes_recv = net_io.bytes_recv

        bytes_sent_diff = bytes_sent - self.network_stats['previous_bytes_sent']
        bytes_recv_diff = bytes_recv - self.network_stats['previous_bytes_recv']

        self.network_stats['previous_bytes_sent'] = bytes_sent
        self.network_stats['previous_bytes_recv'] = bytes_recv

        # Convert bytes per second to Mbps
        bandwidth_sent = (bytes_sent_diff * 8) / (REFRESH_INTERVAL * 1_000_000)
        bandwidth_recv = (bytes_recv_diff * 8) / (REFRESH_INTERVAL * 1_000_000)
        total_bandwidth = bandwidth_sent + bandwidth_recv

        # Update bandwidth history
        current_time = datetime.now().strftime("%H:%M:%S")
        self.network_stats['bandwidth_history'].append(total_bandwidth)
        self.network_stats['time_history'].append(current_time)

        # Maintain only the last 20 data points
        if len(self.network_stats['bandwidth_history']) > 20:
            self.network_stats['bandwidth_history'].pop(0)
            self.network_stats['time_history'].pop(0)

        # Check bandwidth threshold
        self.check_threshold('Bandwidth Usage', total_bandwidth, self.thresholds['bandwidth_usage'])

        # Measure latency and packet loss
        latency, packet_loss = self.measure_network_latency()

        self.check_threshold('Latency', latency, self.thresholds['latency'])
        self.check_threshold('Packet Loss', packet_loss, self.thresholds['packet_loss'])

        # Update network information data
        self.network_information = {
            'bandwidth_usage': total_bandwidth,
            'latency': latency,
            'packet_loss': packet_loss,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }

    def collect_connection_status(self):
        """
        Collect Connection Status Information.
        """
        uptime_seconds = time.time() - psutil.boot_time()
        uptime = str(datetime.utcfromtimestamp(uptime_seconds).strftime("%H:%M:%S"))
        active_connections = len(psutil.net_connections(kind='inet'))
        protocols = self.get_active_protocols()

        # Placeholder for client connection states
        client_status = self.get_client_status()

        # Update connection status data
        self.connection_status = {
            'server_uptime': uptime,
            'active_connections': active_connections,
            'protocols': protocols,
            'client_status': client_status,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }

    def get_active_protocols(self):
        """
        Retrieve active protocols based on current network connections.
        """
        protocols = set()
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == psutil.CONN_ESTABLISHED:
                if conn.type == socket.SOCK_STREAM:
                    protocols.add('TCP')
                elif conn.type == socket.SOCK_DGRAM:
                    protocols.add('UDP')
        return list(protocols)

    def get_client_status(self):
        """
        Placeholder implementation for client connection states.
        """
        # In a real application, track actual client connections and their states
        return {
            'client1': 'Connected',
            'client2': 'Disconnected',
            'client3': 'Connected'
        }

    def measure_network_latency(self):
        """
        Measure latency and packet loss by pinging the server.
        """
        server_ip = '8.8.8.8'  # Use a reliable external server
        ping_count = 4
        timeout = 1  # second
        successful_pings = 0
        total_latency = 0

        for _ in range(ping_count):
            response = ping(server_ip, timeout=timeout)
            if response is not None:
                successful_pings += 1
                total_latency += response * 1000  # convert to ms
            time.sleep(0.1)  # slight delay between pings

        if successful_pings > 0:
            avg_latency = total_latency / successful_pings
            packet_loss = ((ping_count - successful_pings) / ping_count) * 100
        else:
            avg_latency = float('inf')
            packet_loss = 100

        return avg_latency, packet_loss

    def check_threshold(self, metric_name, value, threshold):
        """
        Check if a metric exceeds its threshold and trigger an alert.
        """
        if not isinstance(value, (int, float)):
            return  # Skip if value is not a number

        if value > threshold:
            alert_message = f"{metric_name} has reached {value:.2f} which exceeds the threshold of {threshold}."
            self.trigger_alert(metric_name, alert_message, severity='Critical')
        elif value > threshold * 0.8:
            alert_message = f"{metric_name} is at {value:.2f}, approaching the threshold of {threshold}."
            self.trigger_alert(metric_name, alert_message, severity='Warning')

    def trigger_alert(self, alert_type, message, severity='Critical'):
        """
        Create and store an alert.
        """
        alert = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'type': alert_type,
            'message': message,
            'severity': severity
        }
        with self.lock:
            self.alerts.append(alert)
            self.data_log['alerts'].append(alert)
            self.data_log['alerts'] = self.data_log['alerts'][-100:]  # Limit size

        logging.warning(f"{severity} Alert: {alert_type} - {message}")

        # Show system notification
        notification.notify(
            title=f"{severity} Alert: {alert_type}",
            message=message,
            timeout=5,
            app_name="StatusMonitor"
        )

    def get_status_data(self):
        """
        Retrieve the current status data.
        """
        with self.lock:
            status_data = {
                'connection_status': self.connection_status.copy(),
                'system_health': self.system_health.copy(),
                'network_information': self.network_information.copy(),
                'alerts': self.alerts.copy()
            }
            self.alerts.clear()  # Clear alerts after sending
            return status_data

    def log_data(self):
        """
        Log the collected data into the data log.
        """
        self.data_log['system_health'].append(self.system_health)
        self.data_log['network_information'].append(self.network_information)

        # Limit log size to prevent excessive file growth
        self.data_log['system_health'] = self.data_log['system_health'][-100:]
        self.data_log['network_information'] = self.data_log['network_information'][-100:]

        self.save_data_log()


class StatusWindow(ctk.CTkToplevel):
    """
    GUI window for displaying system and network status.
    """

    def __init__(self, master, status_monitor: StatusMonitor):
        """
        Initializes the StatusWindow.
        """
        super().__init__(master)
        self.title("System Status Monitor")
        self.geometry("1000x800")
        self.status_monitor = status_monitor

        # Register as observer
        self.status_monitor.register_observer(self)

        # Initialize the GUI components
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """
        Create all GUI widgets.
        """
        # Configure grid layout
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create a Notebook for tabs
        self.notebook = ctk.CTkTabview(self, width=900, height=700)
        self.notebook.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Add tabs
        self.notebook.add("Connection Status")
        self.notebook.add("System Health")
        self.notebook.add("Network Information")
        self.notebook.add("Real-Time Alerts")
        self.notebook.add("Historical Data")

        # Initialize each tab
        self.init_connection_status_tab()
        self.init_system_health_tab()
        self.init_network_information_tab()
        self.init_real_time_alerts_tab()
        self.init_historical_data_tab()

    def init_connection_status_tab(self):
        self.connection_frame = self.notebook.tab("Connection Status")
        self.connection_frame.grid_columnconfigure(1, weight=1)

        # Server Uptime
        self.uptime_label = ctk.CTkLabel(self.connection_frame, text="Server Uptime: N/A", anchor="w", font=("Arial", 14))
        self.uptime_label.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

        # Active Connections
        self.active_connections_label = ctk.CTkLabel(self.connection_frame, text="Active Connections: N/A", anchor="w", font=("Arial", 14))
        self.active_connections_label.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        # Protocols
        self.protocols_label = ctk.CTkLabel(self.connection_frame, text="Protocols: N/A", anchor="w", font=("Arial", 14))
        self.protocols_label.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        # Client Status
        self.client_status_label = ctk.CTkLabel(self.connection_frame, text="Client Status:", anchor="w", font=("Arial", 14, "bold"))
        self.client_status_label.grid(row=3, column=0, padx=10, pady=(20, 5), sticky="w")

        self.client_status_text = scrolledtext.ScrolledText(self.connection_frame, height=10, state='disabled', font=("Arial", 12))
        self.client_status_text.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")

    def init_system_health_tab(self):
        self.system_health_frame = self.notebook.tab("System Health")
        self.system_health_frame.grid_columnconfigure(1, weight=1)

        # CPU Usage
        self.cpu_label = ctk.CTkLabel(self.system_health_frame, text="CPU Usage:", anchor="w", font=("Arial", 14))
        self.cpu_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.cpu_progress = ctk.CTkProgressBar(self.system_health_frame, width=300)
        self.cpu_progress.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.cpu_value = ctk.CTkLabel(self.system_health_frame, text="0%", anchor="w", font=("Arial", 14))
        self.cpu_value.grid(row=0, column=2, padx=10, pady=5, sticky="w")

        # Memory Usage
        self.memory_label = ctk.CTkLabel(self.system_health_frame, text="Memory Usage:", anchor="w", font=("Arial", 14))
        self.memory_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.memory_progress = ctk.CTkProgressBar(self.system_health_frame, width=300)
        self.memory_progress.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        self.memory_value = ctk.CTkLabel(self.system_health_frame, text="0%", anchor="w", font=("Arial", 14))
        self.memory_value.grid(row=1, column=2, padx=10, pady=5, sticky="w")

        # Disk Usage
        self.disk_label = ctk.CTkLabel(self.system_health_frame, text="Disk Usage:", anchor="w", font=("Arial", 14))
        self.disk_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.disk_progress = ctk.CTkProgressBar(self.system_health_frame, width=300)
        self.disk_progress.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        self.disk_value = ctk.CTkLabel(self.system_health_frame, text="0%", anchor="w", font=("Arial", 14))
        self.disk_value.grid(row=2, column=2, padx=10, pady=5, sticky="w")

    def init_network_information_tab(self):
        self.network_frame = self.notebook.tab("Network Information")
        self.network_frame.grid_columnconfigure(1, weight=1)

        # Bandwidth Usage
        self.bandwidth_label = ctk.CTkLabel(self.network_frame, text="Bandwidth Usage (Mbps):", anchor="w", font=("Arial", 14))
        self.bandwidth_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.bandwidth_value = ctk.CTkLabel(self.network_frame, text="0.00 Mbps", anchor="w", font=("Arial", 14))
        self.bandwidth_value.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        # Latency
        self.latency_label = ctk.CTkLabel(self.network_frame, text="Latency (ms):", anchor="w", font=("Arial", 14))
        self.latency_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.latency_value = ctk.CTkLabel(self.network_frame, text="0 ms", anchor="w", font=("Arial", 14))
        self.latency_value.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Packet Loss
        self.packet_loss_label = ctk.CTkLabel(self.network_frame, text="Packet Loss (%):", anchor="w", font=("Arial", 14))
        self.packet_loss_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.packet_loss_value = ctk.CTkLabel(self.network_frame, text="0%", anchor="w", font=("Arial", 14))
        self.packet_loss_value.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        # Bandwidth Usage Graph
        self.bandwidth_fig, self.bandwidth_ax = plt.subplots(figsize=(5, 3))
        self.bandwidth_canvas = FigureCanvasTkAgg(self.bandwidth_fig, master=self.network_frame)
        self.bandwidth_canvas.get_tk_widget().grid(row=3, column=0, columnspan=2, padx=10, pady=10)
        self.bandwidth_data = []
        self.bandwidth_time = []

        self.bandwidth_ax.set_title("Bandwidth Usage Over Time")
        self.bandwidth_ax.set_xlabel("Time")
        self.bandwidth_ax.set_ylabel("Mbps")
        self.bandwidth_line, = self.bandwidth_ax.plot([], [], label="Bandwidth (Mbps)", color='cyan')
        self.bandwidth_ax.legend()
        self.bandwidth_ax.grid(True)

    def init_real_time_alerts_tab(self):
        self.alerts_frame = self.notebook.tab("Real-Time Alerts")
        self.alerts_frame.grid_columnconfigure(0, weight=1)

        # Alerts List
        self.alerts_list = scrolledtext.ScrolledText(self.alerts_frame, height=25, state='disabled', font=("Arial", 12))
        self.alerts_list.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Clear Alerts Button
        self.clear_alerts_button = ctk.CTkButton(self.alerts_frame, text="Clear Alerts", command=self.clear_alerts)
        self.clear_alerts_button.grid(row=1, column=0, padx=10, pady=5, sticky="e")

    def init_historical_data_tab(self):
        self.historical_frame = self.notebook.tab("Historical Data")
        self.historical_frame.grid_columnconfigure(0, weight=1)
        self.historical_frame.grid_rowconfigure(0, weight=1)

        # System Health Log
        self.system_health_log = scrolledtext.ScrolledText(self.historical_frame, state='disabled', font=("Arial", 12))
        self.system_health_log.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Network Information Log
        self.network_info_log = scrolledtext.ScrolledText(self.historical_frame, state='disabled', font=("Arial", 12))
        self.network_info_log.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        # Export Logs Button
        self.export_logs_button = ctk.CTkButton(self.historical_frame, text="Export Logs", command=self.export_logs)
        self.export_logs_button.grid(row=2, column=0, padx=10, pady=5, sticky="e")

    def clear_alerts(self):
        """
        Clears the alerts list.
        """
        self.alerts_list.config(state='normal')
        self.alerts_list.delete(1.0, ctk.END)
        self.alerts_list.config(state='disabled')

    def export_logs(self):
        """
        Exports the historical logs to a JSON file.
        """
        try:
            export_file = f"exported_logs_{int(time.time())}.json"
            with open(export_file, 'w') as f:
                json.dump(self.status_monitor.data_log, f, indent=4)
            messagebox.showinfo("Export Successful", f"Logs exported to {export_file}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export logs: {e}")

    def update(self, status_data):
        """
        Update the GUI with new status data.
        """
        self.display_status(status_data)

    def display_status(self, status):
        """
        Update all tabs with the latest status data.
        """
        # Ensure GUI updates happen in the main thread
        self.after(0, self._update_gui, status)

    def _update_gui(self, status):
        """
        Internal method to update GUI widgets.
        """
        # Connection Status
        connection_status = status.get('connection_status', {})
        self.display_connection_status(connection_status)

        # System Health
        system_health = status.get('system_health', {})
        self.display_system_health(system_health)

        # Network Information
        network_info = status.get('network_information', {})
        self.display_network_information(network_info)

        # Real-Time Alerts
        alerts = status.get('alerts', [])
        self.display_real_time_alerts(alerts)

        # Historical Data
        self.display_historical_data()

    def display_connection_status(self, connection_status):
        """
        Display connection status information.
        """
        uptime = connection_status.get('server_uptime', 'N/A')
        active_connections = connection_status.get('active_connections', 'N/A')
        protocols = connection_status.get('protocols', [])
        client_status = connection_status.get('client_status', {})

        self.uptime_label.configure(text=f"Server Uptime: {uptime}")
        self.active_connections_label.configure(text=f"Active Connections: {active_connections}")
        self.protocols_label.configure(text=f"Protocols: {', '.join(protocols) if protocols else 'N/A'}")

        # Display client statuses
        self.client_status_text.config(state='normal')
        self.client_status_text.delete(1.0, ctk.END)
        for client, status in client_status.items():
            self.client_status_text.insert(ctk.END, f"{client}: {status}\n")
        self.client_status_text.config(state='disabled')

    def display_system_health(self, system_health):
        """
        Display system health information with progress bars.
        """
        cpu_usage = system_health.get('cpu_usage', 0)
        memory_usage = system_health.get('memory_usage', 0)
        disk_usage = system_health.get('disk_usage', 0)

        self.cpu_progress.set(cpu_usage / 100)
        self.cpu_value.configure(text=f"{cpu_usage:.1f}%")

        self.memory_progress.set(memory_usage / 100)
        self.memory_value.configure(text=f"{memory_usage:.1f}%")

        self.disk_progress.set(disk_usage / 100)
        self.disk_value.configure(text=f"{disk_usage:.1f}%")

    def display_network_information(self, network_info):
        """
        Display network information with live graphs.
        """
        bandwidth = network_info.get('bandwidth_usage', 0.0)
        latency = network_info.get('latency', 0)
        packet_loss = network_info.get('packet_loss', 0.0)

        self.bandwidth_value.configure(text=f"{bandwidth:.2f} Mbps")
        self.latency_value.configure(text=f"{latency:.2f} ms" if latency != float('inf') else "N/A")
        self.packet_loss_value.configure(text=f"{packet_loss:.1f}%")

        # Update bandwidth graph
        current_time = datetime.now().strftime("%H:%M:%S")
        self.bandwidth_time.append(current_time)
        self.bandwidth_data.append(bandwidth)

        # Keep only the last 20 data points
        if len(self.bandwidth_data) > 20:
            self.bandwidth_data.pop(0)
            self.bandwidth_time.pop(0)

        self.bandwidth_line.set_data(range(len(self.bandwidth_data)), self.bandwidth_data)
        self.bandwidth_ax.set_xlim(0, max(20, len(self.bandwidth_data)))
        self.bandwidth_ax.set_ylim(0, max(10, max(self.bandwidth_data) + 10))
        self.bandwidth_ax.figure.canvas.draw()

    def display_real_time_alerts(self, alerts):
        """
        Display real-time alerts in the alerts tab.
        """
        if not alerts:
            return

        self.alerts_list.config(state='normal')
        for alert in alerts:
            timestamp = alert.get('timestamp', 'N/A')
            alert_type = alert.get('type', 'N/A')
            message = alert.get('message', '')
            severity = alert.get('severity', 'Info')

            if severity == 'Critical':
                color = "#FF0000"  # Red
            elif severity == 'Warning':
                color = "#FFA500"  # Orange
            else:
                color = "#000000"  # Black

            # Insert text with color
            self.alerts_list.insert(ctk.END, f"[{timestamp}] {alert_type}: {message}\n", ("color",))
            self.alerts_list.tag_configure("color", foreground=color)

        self.alerts_list.config(state='disabled')

    def display_historical_data(self):
        """
        Display historical system and network data.
        """
        # System Health Log
        self.system_health_log.config(state='normal')
        self.system_health_log.delete(1.0, ctk.END)
        for entry in self.status_monitor.data_log.get('system_health', []):
            timestamp = entry.get('timestamp', 'N/A')
            cpu = entry.get('cpu_usage', 0)
            memory = entry.get('memory_usage', 0)
            disk = entry.get('disk_usage', 0)
            self.system_health_log.insert(ctk.END, f"[{timestamp}] CPU: {cpu}%, Memory: {memory}%, Disk: {disk}%\n")
        self.system_health_log.config(state='disabled')

        # Network Information Log
        self.network_info_log.config(state='normal')
        self.network_info_log.delete(1.0, ctk.END)
        for entry in self.status_monitor.data_log.get('network_information', []):
            timestamp = entry.get('timestamp', 'N/A')
            bandwidth = entry.get('bandwidth_usage', 0.0)
            latency = entry.get('latency', 'N/A')
            packet_loss = entry.get('packet_loss', 0.0)
            self.network_info_log.insert(ctk.END, f"[{timestamp}] Bandwidth: {bandwidth:.2f} Mbps, Latency: {latency:.2f} ms, Packet Loss: {packet_loss:.1f}%\n")
        self.network_info_log.config(state='disabled')

    def on_closing(self):
        """
        Handle window closing event.
        """
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.status_monitor.unregister_observer(self)
            self.status_monitor.stop()
            self.destroy()


def main():
    """
    Main function to start the StatusMonitor and GUI.
    """
    root = ctk.CTk()
    root.title("Status Monitor Application")
    root.geometry("400x300")

    # Initialize StatusMonitor
    status_monitor = StatusMonitor()

    # Start monitoring
    status_monitor.start()

    # Create Status Window
    status_window = StatusWindow(root, status_monitor)

    # Start the main loop
    root.mainloop()


if __name__ == "__main__":
    main()
