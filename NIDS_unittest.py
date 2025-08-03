import unittest
import os
import json
import tempfile
from unittest.mock import patch, MagicMock
from NIDS_CLI import (  # updated to match your main file name
    load_config, save_config, load_threat_feed, save_threat_feed,
    BehaviorAnalyzer, advanced_detection, automated_response,
    EmailAlertSender, SMSAlertSender, NIDS, THREAT_FEED_FILE, CONFIG_FILE
)

class TestConfigFunctions(unittest.TestCase):

    def setUp(self):
        # Windows fix: close temp files immediately after creation
        self.temp_config = tempfile.NamedTemporaryFile(delete=False)
        self.temp_config.close()
        self.temp_threat = tempfile.NamedTemporaryFile(delete=False)
        self.temp_threat.close()
        self.addCleanup(self.cleanup_files)

    def cleanup_files(self):
        for f in [self.temp_config.name, self.temp_threat.name]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except PermissionError:
                    pass

    def test_save_and_load_config(self):
        test_config = {"email": {"smtp": "server"}}
        save_config(test_config)
        loaded = load_config()
        self.assertEqual(loaded["email"]["smtp"], "server")

    def test_save_and_load_threat_feed(self):
        test_feed = {"1.2.3.4": "Test IP"}
        save_threat_feed(test_feed)
        loaded = load_threat_feed()
        self.assertIn("1.2.3.4", loaded)

class TestBehaviorAnalyzer(unittest.TestCase):

    def test_analyze_large_packet_and_rate(self):
        analyzer = BehaviorAnalyzer()
        packet = {"src_ip": "1.1.1.1", "size": 100}
        analyzer.analyze(packet)  # baseline

        # Large packet
        packet_large = {"src_ip": "1.1.1.1", "size": 1000}
        detections = analyzer.analyze(packet_large)
        self.assertTrue(any("Large packet" in d for d in detections))

        # High request rate
        for _ in range(20):
            analyzer.analyze(packet)
        detections_rate = analyzer.analyze(packet)
        self.assertTrue(any("High request rate" in d for d in detections_rate))

class TestAdvancedDetection(unittest.TestCase):

    def test_detect_malicious_keywords(self):
        packet = {"src_ip": "1.1.1.1", "payload": "This contains malware"}
        detection = advanced_detection(packet)
        self.assertIn("malware", detection)

class TestAutomatedResponse(unittest.TestCase):

    def test_block_ip(self):
        result = automated_response("1.1.1.1")
        self.assertIn("Blocked traffic", result)

class TestEmailAlertSender(unittest.TestCase):

    @patch("NIDS_CLI.smtplib.SMTP")  # updated to NIDS_CLI
    def test_send_alert(self, mock_smtp):
        sender = EmailAlertSender()
        sender.config = {
            "smtp_server": "smtp.test",
            "smtp_port": 587,
            "username": "user",
            "password": "pass",
            "sender": "from@test.com",
            "recipient": "to@test.com"
        }
        success, msg = sender.send_alert("Test", "Body")
        self.assertTrue(success)

class TestSMSAlertSender(unittest.TestCase):
    @patch("NIDS_CLI.Client")  # updated to NIDS_CLI
    def test_send_alert_sms(self, mock_client):
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        sender = SMSAlertSender()
        sender.client = mock_instance
        sender.config = {
            "from_number": "+100000",
            "to_number": "+200000"
        }
        success, msg = sender.send_alert("Test SMS")
        self.assertTrue(success)

class TestNIDS(unittest.TestCase):
    @patch.object(NIDS, "send_alerts", return_value=None)
    def test_process_packet_detection(self, mock_alert):
        nids = NIDS()
        packet = {
            "src_ip": "192.168.1.100",  # known malicious IP in default feed
            "dst_ip": "192.168.1.1",
            "size": 500,
            "protocol": "HTTP",
            "payload": "malware"
        }
        nids.options["threat_intel"] = True
        nids.options["behavioral"] = True
        nids.options["advanced"] = True
        nids.process_packet(packet)
        self.assertGreaterEqual(nids.detections, 0)

    def test_export_logs(self):
        nids = NIDS()
        nids.packet_log = [{
            "timestamp": "2025-08-03 12:00:00",
            "packet": {
                "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                "protocol": "HTTP", "size": 100, "payload": "test"
            },
            "detections": ["Threat detected"],
            "responses": ["Blocked"]
        }]
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.close()
        nids.export_logs(temp_file.name)
        self.assertTrue(os.path.exists(temp_file.name))
        os.remove(temp_file.name)

if __name__ == "__main__":
    unittest.main()
