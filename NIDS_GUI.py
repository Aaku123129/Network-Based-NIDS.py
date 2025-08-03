import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import time
import json
import os
import random
import threading
import csv
import smtplib
import getpass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    from twilio.rest import Client

    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False

# Configuration files
THREAT_FEED_FILE = "threat_feed.json"
CONFIG_FILE = "nids_config.json"


def load_config():
    """Load configuration from file"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(config):
    """Save configuration to file"""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def load_threat_feed():
    """Load threat intelligence feed"""
    if os.path.exists(THREAT_FEED_FILE):
        with open(THREAT_FEED_FILE, "r") as f:
            return json.load(f)
    return {
        "192.168.1.100": "Known malicious IP",
        "10.0.0.99": "Botnet node",
        "185.143.223.15": "Cryptocurrency miner"
    }


def save_threat_feed(data):
    """Save threat intelligence feed"""
    with open(THREAT_FEED_FILE, "w") as f:
        json.dump(data, f, indent=4)


# Initialize data
THREAT_FEED = load_threat_feed()
CONFIG = load_config()


class BehaviorAnalyzer:
    """Analyzes network behavior for anomalies"""

    def __init__(self):
        self.baseline = {}
        self.request_threshold = 15  # Max requests per minute per IP
        self.request_counts = {}

    def analyze(self, packet):
        """Analyze packet for behavioral anomalies"""
        src_ip = packet.get("src_ip")
        size = packet.get("size")

        # Packet size analysis
        avg_size = self.baseline.get(src_ip, {}).get("size", size)
        self.baseline.setdefault(src_ip, {})["size"] = (avg_size + size) / 2

        # Request rate analysis
        current_minute = int(time.time() / 60)
        if src_ip not in self.request_counts:
            self.request_counts[src_ip] = {"count": 0, "minute": current_minute}

        if self.request_counts[src_ip]["minute"] != current_minute:
            self.request_counts[src_ip] = {"count": 1, "minute": current_minute}
        else:
            self.request_counts[src_ip]["count"] += 1

        detections = []
        if size > avg_size * 2:
            detections.append(f"Anomaly: Large packet size from {src_ip}")
        if self.request_counts[src_ip]["count"] > self.request_threshold:
            detections.append(f"Anomaly: High request rate from {src_ip}")

        return detections if detections else None


def advanced_detection(packet):
    """Detects known attack patterns"""
    suspicious_keywords = [
        "suspicious", "malware", "exploit", "attack",
        "injection", "xss", "sql", "brute force",
        "ddos", "phishing", "ransomware"
    ]
    payload = packet.get("payload", "").lower()
    for keyword in suspicious_keywords:
        if keyword in payload:
            return f"Signature: '{keyword}' in payload from {packet['src_ip']}"
    return None


def automated_response(ip):
    """Simulates automated response to threats"""
    return f"Blocked traffic from {ip}"


class EmailAlertSender:
    """Handles email alert configuration and sending"""

    def __init__(self):
        self.config = CONFIG.get("email", {})
        if not self.config:
            self.configure_email()

    def configure_email(self):
        """Interactive email configuration"""
        # This will now be handled through the GUI
        pass

    def send_alert(self, subject, body):
        """Send email alert"""
        if not self.config:
            return False, "Email not configured"

        try:
            msg = MIMEMultipart()
            msg["From"] = self.config["sender"]
            msg["To"] = self.config["recipient"]
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"]) as server:
                server.starttls()
                server.login(self.config["username"], self.config["password"])
                server.send_message(msg)
            return True, "Email sent successfully"
        except Exception as e:
            return False, f"Email failed: {str(e)}"


class SMSAlertSender:
    """Handles SMS alert configuration and sending"""

    def __init__(self):
        self.config = CONFIG.get("sms", {})
        self.client = None
        if TWILIO_AVAILABLE and self.config:
            try:
                self.client = Client(self.config["account_sid"], self.config["auth_token"])
            except Exception as e:
                print(f"Twilio initialization failed: {str(e)}")

    def configure_sms(self):
        """Interactive SMS configuration"""
        # This will now be handled through the GUI
        pass

    def send_alert(self, message):
        """Send SMS alert"""
        if not TWILIO_AVAILABLE or not self.client:
            return False, "SMS not configured"

        try:
            self.client.messages.create(
                body=message[:160],  # SMS length limit
                from_=self.config["from_number"],
                to=self.config["to_number"]
            )
            return True, "SMS sent successfully"
        except Exception as e:
            return False, f"SMS failed: {str(e)}"


class NIDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Intrusion Detection System")
        self.root.geometry("1000x700")

        # Initialize NIDS components
        self.nids = NIDS()
        self.nids.email_sender = EmailAlertSender()
        self.nids.sms_sender = SMSAlertSender()

        # Create tabs
        self.create_tabs()

        # Initialize UI
        self.setup_main_tab()
        self.setup_config_tab()
        self.setup_threat_tab()
        self.setup_monitor_tab()

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def create_tabs(self):
        """Create the notebook with tabs"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create frames for each tab
        self.main_tab = ttk.Frame(self.notebook)
        self.config_tab = ttk.Frame(self.notebook)
        self.threat_tab = ttk.Frame(self.notebook)
        self.monitor_tab = ttk.Frame(self.notebook)

        # Add tabs to notebook
        self.notebook.add(self.main_tab, text="Main")
        self.notebook.add(self.config_tab, text="Configuration")
        self.notebook.add(self.threat_tab, text="Threat Intelligence")
        self.notebook.add(self.monitor_tab, text="Monitoring")

    def setup_main_tab(self):
        """Setup the main tab with welcome and quick actions"""
        welcome_frame = ttk.LabelFrame(self.main_tab, text="Welcome to NIDS")
        welcome_frame.pack(pady=10, padx=10, fill=tk.X)

        welcome_text = ("Network Intrusion Detection System\n\n"
                        "This system monitors network traffic for suspicious activity\n"
                        "and potential security threats.")
        ttk.Label(welcome_frame, text=welcome_text).pack(pady=10)

        # Quick action buttons
        action_frame = ttk.Frame(self.main_tab)
        action_frame.pack(pady=10)

        ttk.Button(action_frame, text="Start Monitoring",
                   command=lambda: self.notebook.select(self.monitor_tab)).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="Configure Alerts",
                   command=lambda: self.notebook.select(self.config_tab)).grid(row=0, column=1, padx=5)
        ttk.Button(action_frame, text="View Threats",
                   command=lambda: self.notebook.select(self.threat_tab)).grid(row=0, column=2, padx=5)

        # System status
        status_frame = ttk.LabelFrame(self.main_tab, text="System Status")
        status_frame.pack(pady=10, padx=10, fill=tk.X)

        self.status_labels = {
            "monitoring": ttk.Label(status_frame, text="Monitoring: Stopped"),
            "packets": ttk.Label(status_frame, text="Packets Analyzed: 0"),
            "threats": ttk.Label(status_frame, text="Threats Detected: 0"),
            "baseline": ttk.Label(status_frame, text="Behavioral Baseline: 0 IPs"),
            "threat_feed": ttk.Label(status_frame, text="Threat Feed Entries: 0")
        }

        for label in self.status_labels.values():
            label.pack(anchor=tk.W)

    def setup_config_tab(self):
        """Setup the configuration tab"""
        # Email Configuration
        email_frame = ttk.LabelFrame(self.config_tab, text="Email Alerts")
        email_frame.pack(pady=5, padx=10, fill=tk.X)

        self.email_vars = {
            "enabled": tk.BooleanVar(value=self.nids.options["email_alert"]),
            "smtp_server": tk.StringVar(value=self.nids.email_sender.config.get("smtp_server", "")),
            "smtp_port": tk.StringVar(value=self.nids.email_sender.config.get("smtp_port", "587")),
            "username": tk.StringVar(value=self.nids.email_sender.config.get("username", "")),
            "password": tk.StringVar(value=self.nids.email_sender.config.get("password", "")),
            "sender": tk.StringVar(value=self.nids.email_sender.config.get("sender", "")),
            "recipient": tk.StringVar(value=self.nids.email_sender.config.get("recipient", ""))
        }

        ttk.Checkbutton(email_frame, text="Enable Email Alerts",
                        variable=self.email_vars["enabled"]).grid(row=0, column=0, columnspan=2, sticky=tk.W)

        ttk.Label(email_frame, text="SMTP Server:").grid(row=1, column=0, sticky=tk.E)
        ttk.Entry(email_frame, textvariable=self.email_vars["smtp_server"]).grid(row=1, column=1, sticky=tk.EW)

        ttk.Label(email_frame, text="SMTP Port:").grid(row=2, column=0, sticky=tk.E)
        ttk.Entry(email_frame, textvariable=self.email_vars["smtp_port"]).grid(row=2, column=1, sticky=tk.EW)

        ttk.Label(email_frame, text="Username:").grid(row=3, column=0, sticky=tk.E)
        ttk.Entry(email_frame, textvariable=self.email_vars["username"]).grid(row=3, column=1, sticky=tk.EW)

        ttk.Label(email_frame, text="Password:").grid(row=4, column=0, sticky=tk.E)
        ttk.Entry(email_frame, textvariable=self.email_vars["password"], show="*").grid(row=4, column=1, sticky=tk.EW)

        ttk.Label(email_frame, text="Sender Email:").grid(row=5, column=0, sticky=tk.E)
        ttk.Entry(email_frame, textvariable=self.email_vars["sender"]).grid(row=5, column=1, sticky=tk.EW)

        ttk.Label(email_frame, text="Recipient Email:").grid(row=6, column=0, sticky=tk.E)
        ttk.Entry(email_frame, textvariable=self.email_vars["recipient"]).grid(row=6, column=1, sticky=tk.EW)

        # SMS Configuration
        sms_frame = ttk.LabelFrame(self.config_tab, text="SMS Alerts")
        sms_frame.pack(pady=5, padx=10, fill=tk.X)

        self.sms_vars = {
            "enabled": tk.BooleanVar(value=self.nids.options["sms_alert"]),
            "account_sid": tk.StringVar(value=self.nids.sms_sender.config.get("account_sid", "")),
            "auth_token": tk.StringVar(value=self.nids.sms_sender.config.get("auth_token", "")),
            "from_number": tk.StringVar(value=self.nids.sms_sender.config.get("from_number", "")),
            "to_number": tk.StringVar(value=self.nids.sms_sender.config.get("to_number", ""))
        }

        ttk.Checkbutton(sms_frame, text="Enable SMS Alerts",
                        variable=self.sms_vars["enabled"]).grid(row=0, column=0, columnspan=2, sticky=tk.W)

        ttk.Label(sms_frame, text="Account SID:").grid(row=1, column=0, sticky=tk.E)
        ttk.Entry(sms_frame, textvariable=self.sms_vars["account_sid"]).grid(row=1, column=1, sticky=tk.EW)

        ttk.Label(sms_frame, text="Auth Token:").grid(row=2, column=0, sticky=tk.E)
        ttk.Entry(sms_frame, textvariable=self.sms_vars["auth_token"], show="*").grid(row=2, column=1, sticky=tk.EW)

        ttk.Label(sms_frame, text="From Number:").grid(row=3, column=0, sticky=tk.E)
        ttk.Entry(sms_frame, textvariable=self.sms_vars["from_number"]).grid(row=3, column=1, sticky=tk.EW)

        ttk.Label(sms_frame, text="To Number:").grid(row=4, column=0, sticky=tk.E)
        ttk.Entry(sms_frame, textvariable=self.sms_vars["to_number"]).grid(row=4, column=1, sticky=tk.EW)

        # Detection Options
        options_frame = ttk.LabelFrame(self.config_tab, text="Detection Options")
        options_frame.pack(pady=5, padx=10, fill=tk.X)

        self.option_vars = {
            "behavioral": tk.BooleanVar(value=self.nids.options["behavioral"]),
            "threat_intel": tk.BooleanVar(value=self.nids.options["threat_intel"]),
            "advanced": tk.BooleanVar(value=self.nids.options["advanced"]),
            "response": tk.BooleanVar(value=self.nids.options["response"]),
            "auto_stop": tk.StringVar(value=str(self.nids.options["auto_stop"]))
        }

        ttk.Checkbutton(options_frame, text="Behavioral Analysis",
                        variable=self.option_vars["behavioral"]).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Threat Intelligence",
                        variable=self.option_vars["threat_intel"]).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Advanced Detection",
                        variable=self.option_vars["advanced"]).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Automated Response",
                        variable=self.option_vars["response"]).grid(row=3, column=0, sticky=tk.W)

        ttk.Label(options_frame, text="Auto-Stop (seconds):").grid(row=4, column=0, sticky=tk.E)
        ttk.Entry(options_frame, textvariable=self.option_vars["auto_stop"], width=10).grid(row=4, column=1,
                                                                                            sticky=tk.W)

        # Save button
        ttk.Button(self.config_tab, text="Save Configuration",
                   command=self.save_configuration).pack(pady=10)

    def setup_threat_tab(self):
        """Setup the threat intelligence tab"""
        # Threat list
        list_frame = ttk.LabelFrame(self.threat_tab, text="Threat Intelligence Feed")
        list_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

        columns = ("IP", "Description")
        self.threat_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        self.threat_tree.heading("IP", text="IP Address")
        self.threat_tree.heading("Description", text="Description")
        self.threat_tree.column("IP", width=150)
        self.threat_tree.column("Description", width=400)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.threat_tree.pack(fill=tk.BOTH, expand=True)

        # Add/Remove controls
        control_frame = ttk.Frame(self.threat_tab)
        control_frame.pack(pady=5, padx=10, fill=tk.X)

        self.new_ip_var = tk.StringVar()
        self.new_desc_var = tk.StringVar()

        ttk.Label(control_frame, text="IP:").grid(row=0, column=0)
        ttk.Entry(control_frame, textvariable=self.new_ip_var).grid(row=0, column=1)
        ttk.Label(control_frame, text="Description:").grid(row=0, column=2)
        ttk.Entry(control_frame, textvariable=self.new_desc_var).grid(row=0, column=3)
        ttk.Button(control_frame, text="Add Threat",
                   command=self.add_threat).grid(row=0, column=4, padx=5)
        ttk.Button(control_frame, text="Remove Selected",
                   command=self.remove_threat).grid(row=0, column=5)

        # Load threats
        self.update_threat_list()

    def setup_monitor_tab(self):
        """Setup the monitoring tab"""
        # Log display
        log_frame = ttk.LabelFrame(self.monitor_tab, text="Monitoring Log")
        log_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Controls
        control_frame = ttk.Frame(self.monitor_tab)
        control_frame.pack(pady=5, padx=10, fill=tk.X)

        ttk.Button(control_frame, text="Start Monitoring",
                   command=self.start_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop Monitoring",
                   command=self.stop_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Logs",
                   command=self.export_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Log",
                   command=self.clear_log).pack(side=tk.LEFT, padx=5)

    def update_threat_list(self):
        """Update the threat list display"""
        self.threat_tree.delete(*self.threat_tree.get_children())
        for ip, desc in THREAT_FEED.items():
            self.threat_tree.insert("", tk.END, values=(ip, desc))

    def add_threat(self):
        """Add a new threat to the feed"""
        ip = self.new_ip_var.get().strip()
        desc = self.new_desc_var.get().strip()

        if not ip:
            messagebox.showerror("Error", "IP address cannot be empty")
            return

        THREAT_FEED[ip] = desc
        save_threat_feed(THREAT_FEED)
        self.update_threat_list()
        self.new_ip_var.set("")
        self.new_desc_var.set("")

    def remove_threat(self):
        """Remove the selected threat"""
        selected = self.threat_tree.selection()
        if not selected:
            messagebox.showerror("Error", "No threat selected")
            return

        for item in selected:
            ip = self.threat_tree.item(item, "values")[0]
            del THREAT_FEED[ip]

        save_threat_feed(THREAT_FEED)
        self.update_threat_list()

    def save_configuration(self):
        """Save all configuration settings"""
        # Email config
        self.nids.email_sender.config = {
            "smtp_server": self.email_vars["smtp_server"].get(),
            "smtp_port": int(self.email_vars["smtp_port"].get()),
            "username": self.email_vars["username"].get(),
            "password": self.email_vars["password"].get(),
            "sender": self.email_vars["sender"].get(),
            "recipient": self.email_vars["recipient"].get()
        }

        # SMS config
        self.nids.sms_sender.config = {
            "account_sid": self.sms_vars["account_sid"].get(),
            "auth_token": self.sms_vars["auth_token"].get(),
            "from_number": self.sms_vars["from_number"].get(),
            "to_number": self.sms_vars["to_number"].get()
        }

        # Options
        self.nids.options = {
            "behavioral": self.option_vars["behavioral"].get(),
            "threat_intel": self.option_vars["threat_intel"].get(),
            "advanced": self.option_vars["advanced"].get(),
            "response": self.option_vars["response"].get(),
            "email_alert": self.email_vars["enabled"].get(),
            "sms_alert": self.sms_vars["enabled"].get(),
            "auto_stop": int(self.option_vars["auto_stop"].get())
        }

        # Save to file
        CONFIG["email"] = self.nids.email_sender.config
        CONFIG["sms"] = self.nids.sms_sender.config
        CONFIG["options"] = self.nids.options
        save_config(CONFIG)

        messagebox.showinfo("Success", "Configuration saved successfully")

    def start_monitoring(self):
        """Start the monitoring process"""
        if self.nids.running:
            messagebox.showwarning("Warning", "Monitoring is already running")
            return

        self.nids.running = True
        self.nids.packet_log = []
        self.nids.total_packets = 0
        self.nids.detections = 0

        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.run_monitoring, daemon=True)
        monitor_thread.start()

        # Update UI
        self.status_labels["monitoring"].config(text="Monitoring: Running")
        self.log_text.insert(tk.END, "=== Monitoring Started ===\n")
        self.log_text.see(tk.END)
        self.status_var.set("Monitoring started")

    def stop_monitoring(self):
        """Stop the monitoring process"""
        if not self.nids.running:
            messagebox.showwarning("Warning", "Monitoring is not running")
            return

        self.nids.running = False
        self.status_labels["monitoring"].config(text="Monitoring: Stopped")
        self.log_text.insert(tk.END, "\n=== Monitoring Stopped ===\n")
        self.log_text.see(tk.END)
        self.status_var.set("Monitoring stopped")

    def run_monitoring(self):
        """Run the monitoring loop"""
        while self.nids.running:
            packet = self.nids.generate_packet()
            self.process_packet(packet)
            time.sleep(random.uniform(0.1, 0.5))

    def process_packet(self, packet):
        """Process a network packet and update UI"""
        self.nids.total_packets += 1
        detections = []
        responses = []

        # Threat intelligence check
        if self.nids.options["threat_intel"] and packet["src_ip"] in THREAT_FEED:
            detections.append(f"Threat: {THREAT_FEED[packet['src_ip']]}")

        # Behavioral analysis
        if self.nids.options["behavioral"]:
            behavior_detections = self.nids.behavior.analyze(packet)
            if behavior_detections:
                detections.extend(behavior_detections)

        # Advanced detection
        if self.nids.options["advanced"]:
            adv = advanced_detection(packet)
            if adv:
                detections.append(adv)

        # Automated response
        if self.nids.options["response"] and detections:
            responses.append(automated_response(packet["src_ip"]))

        # Log the packet
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "packet": packet,
            "detections": detections,
            "responses": responses
        }
        self.nids.packet_log.append(log_entry)

        # Update UI
        self.update_packet_display(log_entry)

        # Send alerts if needed
        if detections:
            self.nids.detections += 1
            self.send_alerts(log_entry)

        # Update status
        self.root.after(0, self.update_status)

    def update_packet_display(self, log_entry):
        """Update the log display with a new packet"""
        pkt = log_entry["packet"]
        log_line = f"\n[{log_entry['timestamp']}] {pkt['protocol']} {pkt['src_ip']} -> {pkt['dst_ip']}\n"
        log_line += f"Size: {pkt['size']} bytes | Payload: {pkt['payload'][:50]}...\n"

        for d in log_entry["detections"]:
            log_line += f"  [!] {d}\n"
        for r in log_entry["responses"]:
            log_line += f"  [Action] {r}\n"

        self.log_text.insert(tk.END, log_line)
        self.log_text.see(tk.END)

    def send_alerts(self, log_entry):
        """Send email and SMS alerts"""
        if not (self.nids.options["email_alert"] or self.nids.options["sms_alert"]):
            return

        alert_msg = f"NIDS Alert at {log_entry['timestamp']}:\n"
        alert_msg += "\n".join(log_entry["detections"]) + "\n\n"
        alert_msg += f"Packet Details:\nProtocol: {log_entry['packet']['protocol']}\n"
        alert_msg += f"Source: {log_entry['packet']['src_ip']}\n"
        alert_msg += f"Destination: {log_entry['packet']['dst_ip']}\n"
        alert_msg += f"Size: {log_entry['packet']['size']} bytes\n"
        alert_msg += f"Payload: {log_entry['packet']['payload']}"

        # Email alert
        if self.nids.options["email_alert"]:
            success, msg = self.nids.email_sender.send_alert(
                "NIDS Security Alert",
                alert_msg
            )
            self.log_text.insert(tk.END, f"  [Email] {msg}\n")

        # SMS alert
        if self.nids.options["sms_alert"]:
            sms_msg = "ALERT: " + ", ".join(d[:20] for d in log_entry["detections"])
            success, msg = self.nids.sms_sender.send_alert(sms_msg)
            self.log_text.insert(tk.END, f"  [SMS] {msg}\n")

        self.log_text.see(tk.END)

    def update_status(self):
        """Update the status display"""
        self.status_labels["packets"].config(text=f"Packets Analyzed: {self.nids.total_packets}")
        self.status_labels["threats"].config(text=f"Threats Detected: {self.nids.detections}")
        self.status_labels["baseline"].config(text=f"Behavioral Baseline: {len(self.nids.behavior.baseline)} IPs")
        self.status_labels["threat_feed"].config(text=f"Threat Feed Entries: {len(THREAT_FEED)}")

    def export_logs(self):
        """Export logs to CSV file"""
        if not self.nids.packet_log:
            messagebox.showwarning("Warning", "No logs to export")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", newline="") as csvfile:
                fieldnames = [
                    "timestamp", "src_ip", "dst_ip", "protocol",
                    "size", "payload", "detections", "responses"
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for entry in self.nids.packet_log:
                    pkt = entry["packet"]
                    writer.writerow({
                        "timestamp": entry["timestamp"],
                        "src_ip": pkt["src_ip"],
                        "dst_ip": pkt["dst_ip"],
                        "protocol": pkt["protocol"],
                        "size": pkt["size"],
                        "payload": pkt["payload"],
                        "detections": " | ".join(entry["detections"]),
                        "responses": " | ".join(entry["responses"]),
                    })

            messagebox.showinfo("Success", f"Logs exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {e}")

    def clear_log(self):
        """Clear the log display"""
        self.log_text.delete(1.0, tk.END)


class NIDS:
    """Main Network Intrusion Detection System class"""

    def __init__(self):
        self.running = False
        self.behavior = BehaviorAnalyzer()
        self.packet_log = []
        self.total_packets = 0
        self.detections = 0
        self.email_sender = EmailAlertSender()
        self.sms_sender = SMSAlertSender()
        self.options = CONFIG.get("options", {
            "behavioral": True,
            "threat_intel": True,
            "advanced": True,
            "response": True,
            "email_alert": bool(self.email_sender.config),
            "sms_alert": bool(self.sms_sender.config and TWILIO_AVAILABLE),
            "auto_stop": 30  # Default to 30 seconds
        })

    def generate_packet(self):
        """Generate simulated network packet"""
        protocols = ["HTTP", "HTTPS", "FTP", "SSH", "DNS", "SMTP", "RDP"]
        return {
            "src_ip": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "dst_ip": "192.168.1.1",
            "size": random.randint(50, 2000),
            "protocol": random.choice(protocols),
            "payload": random.choice([
                "normal traffic",
                "suspicious activity detected",
                "login attempt",
                "malware signature found",
                "SQL injection attempt",
                "XSS attempt <script>alert(1)</script>",
                "brute force attack in progress",
                "DDoS traffic detected",
                "regular HTTP request"
            ])
        }


if __name__ == "__main__":
    root = tk.Tk()
    app = NIDSGUI(root)
    root.mainloop()