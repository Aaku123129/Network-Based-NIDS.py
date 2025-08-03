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
        print("\n=== Email Alert Configuration ===")
        print("Leave fields blank to skip email configuration")

        smtp_server = input("SMTP Server (e.g., smtp.gmail.com): ").strip()
        if not smtp_server:
            return

        self.config = {
            "smtp_server": smtp_server,
            "smtp_port": int(input("SMTP Port (e.g., 587): ")),
            "username": input("Email Address: ").strip(),
            "password": getpass.getpass("Email Password/App Password: "),
            "sender": input("Sender Email: ").strip(),
            "recipient": input("Recipient Email: ").strip()
        }

        # Test configuration
        try:
            with smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"]) as server:
                server.starttls()
                server.login(self.config["username"], self.config["password"])
            print("✓ Email configuration verified and saved")
            CONFIG["email"] = self.config
            save_config(CONFIG)
        except Exception as e:
            print(f"✗ Email configuration failed: {str(e)}")
            self.config = {}

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
        if not TWILIO_AVAILABLE:
            print("Twilio not available. Install with: pip install twilio")
            return
        print("\n=== SMS Alert Configuration ===")
        print("Leave fields blank to skip SMS configuration")
        account_sid = input("Twilio Account SID: ").strip()
        if not account_sid:
            return
        self.config = {
            "account_sid": account_sid,
            "auth_token": getpass.getpass("Twilio Auth Token: "),
            "from_number": input("Twilio Phone Number (e.g., +1234567890): ").strip(),
            "to_number": input("Your Verified Phone Number (e.g., +1987654321): ").strip()
        }
        try:
            self.client = Client(self.config["account_sid"], self.config["auth_token"])
            self.client.messages.create(
                body="NIDS test message",
                from_=self.config["from_number"],
                to=self.config["to_number"]
            )
            print("✓ SMS configuration verified and saved")
            CONFIG["sms"] = self.config
            save_config(CONFIG)
        except Exception as e:
            print(f"✗ SMS configuration failed: {str(e)}")
            self.config = {}

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

    def save_options(self):
        """Save current options to config"""
        CONFIG["options"] = self.options
        save_config(CONFIG)

    def show_menu(self):
        """Display main menu and handle user input"""
        while True:
            print("\n=== NIDS Main Menu ===")
            print("1. Configure Alert Settings")
            print("2. Toggle Detection Features")
            print("3. View/Edit Threat Intelligence")
            print("4. Start Monitoring")
            print("5. Exit")

            choice = input("Select an option (1-5): ").strip()

            if choice == "1":
                self.configure_alerts()
            elif choice == "2":
                self.toggle_features()
            elif choice == "3":
                self.view_threat_intel()
            elif choice == "4":
                self.start_monitoring()
            elif choice == "5":
                break
            else:
                print("Invalid choice. Please try again.")

    def configure_alerts(self):
        """Configure alert settings"""
        while True:
            print("\n=== Alert Configuration ===")
            print(f"1. Email Alerts: {'ENABLED' if self.options['email_alert'] else 'DISABLED'}")
            print(f"2. SMS Alerts: {'ENABLED' if self.options['sms_alert'] else 'DISABLED'}")
            print(f"3. Auto-Stop Timer: {self.options['auto_stop']} seconds")
            print("4. Back to Main Menu")

            choice = input("Select an option (1-4): ").strip()

            if choice == "1":
                self.email_sender.configure_email()
                self.options["email_alert"] = bool(self.email_sender.config)
                self.save_options()
            elif choice == "2":
                self.sms_sender.configure_sms()
                self.options["sms_alert"] = bool(self.sms_sender.config and TWILIO_AVAILABLE)
                self.save_options()
            elif choice == "3":
                self.set_auto_stop()
            elif choice == "4":
                break
            else:
                print("Invalid choice. Please try again.")

    def set_auto_stop(self):
        """Set auto-stop timer in seconds"""
        try:
            seconds = int(input("Enter auto-stop time in seconds (0 for manual stop): "))
            self.options["auto_stop"] = max(0, seconds)  # Ensure non-negative
            self.save_options()
            print(f"Auto-stop set to {seconds} seconds.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    def toggle_features(self):
        """Toggle detection features on/off"""
        print("\n=== Toggle Detection Features ===")
        features = [
            ("Behavioral Analysis", "behavioral"),
            ("Threat Intelligence", "threat_intel"),
            ("Advanced Detection", "advanced"),
            ("Automated Response", "response")
        ]
        for i, (name, key) in enumerate(features, 1):
            status = "ON" if self.options[key] else "OFF"
            print(f"{i}. {name}: [{status}]")

        print("\nEnter numbers to toggle (comma-separated, e.g., '1,3')")
        print("Press Enter to go back")
        selections = input("Your selection: ").strip()
        if not selections:
            return
        for sel in selections.split(","):
            try:
                idx = int(sel.strip()) - 1
                if 0 <= idx < len(features):
                    key = features[idx][1]
                    self.options[key] = not self.options[key]
            except (ValueError, IndexError):
                print(f"Invalid selection: {sel}")
        self.save_options()
        print("Features updated.")

    def view_threat_intel(self):
        """View and manage threat intelligence"""
        while True:
            print("\n=== Threat Intelligence Feed ===")
            for ip, description in THREAT_FEED.items():
                print(f"{ip}: {description}")
            print("\nOptions:")
            print("1. Add new threat")
            print("2. Remove threat")
            print("3. Back to menu")
            choice = input("Select an option (1-3): ").strip()
            if choice == "1":
                ip = input("Enter IP address: ").strip()
                desc = input("Enter description: ").strip()
                THREAT_FEED[ip] = desc
                save_threat_feed(THREAT_FEED)
                print("Threat added.")
            elif choice == "2":
                ip = input("Enter IP address to remove: ").strip()
                if ip in THREAT_FEED:
                    del THREAT_FEED[ip]
                    save_threat_feed(THREAT_FEED)
                    print("Threat removed.")
                else:
                    print("IP not found in threat feed.")
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")

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

    def start_monitoring(self):
        """Start the NIDS monitoring"""
        self.running = True
        run_time = self.options["auto_stop"]

        if run_time > 0:
            threading.Timer(run_time, self.stop).start()
            print(f"\n[*] NIDS Started (will auto-stop in {run_time} seconds)...")
        else:
            print("\n[*] NIDS Started (press Ctrl+C to stop)...")

        # Reset counters
        self.packet_log = []
        self.total_packets = 0
        self.detections = 0

        # Start monitoring in background thread
        monitor_thread = threading.Thread(target=self.run, daemon=True)
        monitor_thread.start()

        try:
            while self.running and monitor_thread.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

        # Finalize
        self.export_logs()
        self.print_summary()

    def stop(self):
        """Stop the NIDS monitoring"""
        self.running = False
        print("\n[!] Stopping NIDS...")

    def run(self):
        """Main monitoring loop"""
        print("\n[ Monitoring Started ]")
        print("======================")

        while self.running:
            packet = self.generate_packet()
            self.process_packet(packet)
            time.sleep(random.uniform(0.1, 0.5))  # Realistic timing

    def process_packet(self, packet):
        """Process and analyze a network packet"""
        self.total_packets += 1
        detections = []
        responses = []

        # Threat intelligence check
        if self.options["threat_intel"] and packet["src_ip"] in THREAT_FEED:
            detections.append(f"Threat: {THREAT_FEED[packet['src_ip']]}")

        # Behavioral analysis
        if self.options["behavioral"]:
            behavior_detections = self.behavior.analyze(packet)
            if behavior_detections:
                detections.extend(behavior_detections)

        # Advanced detection
        if self.options["advanced"]:
            adv = advanced_detection(packet)
            if adv:
                detections.append(adv)

        # Automated response
        if self.options["response"] and detections:
            responses.append(automated_response(packet["src_ip"]))

        # Log the packet
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "packet": packet,
            "detections": detections,
            "responses": responses
        }
        self.packet_log.append(log_entry)

        # Print to console
        self.print_packet(log_entry)

        # Send alerts if needed
        if detections:
            self.detections += 1
            self.send_alerts(log_entry)

    def print_packet(self, log_entry):
        """Print packet information to console"""
        pkt = log_entry["packet"]
        print(f"\n[{log_entry['timestamp']}] {pkt['protocol']} {pkt['src_ip']} -> {pkt['dst_ip']}")
        print(f"Size: {pkt['size']} bytes | Payload: {pkt['payload'][:50]}...")

        for d in log_entry["detections"]:
            print(f"  [!] {d}")
        for r in log_entry["responses"]:
            print(f"  [Action] {r}")

    def send_alerts(self, log_entry):
        """Send email and SMS alerts"""
        if not (self.options["email_alert"] or self.options["sms_alert"]):
            return

        alert_msg = f"NIDS Alert at {log_entry['timestamp']}:\n"
        alert_msg += "\n".join(log_entry["detections"]) + "\n\n"
        alert_msg += f"Packet Details:\nProtocol: {log_entry['packet']['protocol']}\n"
        alert_msg += f"Source: {log_entry['packet']['src_ip']}\n"
        alert_msg += f"Destination: {log_entry['packet']['dst_ip']}\n"
        alert_msg += f"Size: {log_entry['packet']['size']} bytes\n"
        alert_msg += f"Payload: {log_entry['packet']['payload']}"

        # Email alert
        if self.options["email_alert"]:
            success, msg = self.email_sender.send_alert(
                "NIDS Security Alert",
                alert_msg
            )
            print(f"  [Email] {msg}")

        # SMS alert (shorter message)
        if self.options["sms_alert"]:
            sms_msg = "ALERT: " + ", ".join(d[:20] for d in log_entry["detections"])
            success, msg = self.sms_sender.send_alert(sms_msg)
            print(f"  [SMS] {msg}")

    def export_logs(self, file_path="nids_logs.csv"):
        """Export logs to CSV file"""
        try:
            with open(file_path, "w", newline="") as csvfile:
                fieldnames = [
                    "timestamp", "src_ip", "dst_ip", "protocol",
                    "size", "payload", "detections", "responses"
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for entry in self.packet_log:
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
            print(f"\n[+] Logs exported to {file_path}")
        except Exception as e:
            print(f"\n[!] Failed to export logs: {e}")

    def print_summary(self):
        """Print monitoring summary"""
        print("\n=== Monitoring Summary ===")
        print(f"Duration: {len(self.packet_log)} seconds")
        print(f"Packets Analyzed: {self.total_packets}")
        print(f"Threats Detected: {self.detections}")
        if self.total_packets > 0:
            detection_rate = (self.detections / self.total_packets) * 100
            print(f"Detection Rate: {detection_rate:.2f}%")
        print(f"Behavioral Baseline: {len(self.behavior.baseline)} IPs")
        print(f"Threat Feed Entries: {len(THREAT_FEED)}")


if __name__ == "__main__":
    print("=== Network Intrusion Detection System ===")
    print("Version 2.1 - With Configurable Timer in Seconds")

    # Initialize and run
    nids = NIDS()
    nids.show_menu()

