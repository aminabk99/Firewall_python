import random
import time
from collections import defaultdict
import os

# Configurations
THRESHOLD = 5  # Block if more than 5 packets in one session
WHITELIST = {"192.168.1.1", "127.0.0.1"} # Trusted IPs
MALICIOUS_SIGNATURE = "GET /scripts/root.exe" # Example: Nimda worm signature

def log_event(ip, action, reason=""):
    """Creates a logs folder and saves event details with timestamps."""
    if not os.path.exists("logs"):
        os.makedirs("logs") #
    
    filename = f"logs/firewall_{time.strftime('%Y%m%d')}.txt"
    with open(filename, "a") as f:
        timestamp = time.strftime("%H:%M:%S")
        f.write(f"[{timestamp}] IP: {ip} | ACTION: {action} | REASON: {reason}\n")

def is_malicious_payload(payload):
    """Simple string-based signature detection."""
    return MALICIOUS_SIGNATURE in payload #

def run_firewall():
    blacklist = set()
    packet_counts = defaultdict(int)
    
    print("--- Pro Mini Firewall Active ---")
    print(f"Monitoring for DoS (Threshold: {THRESHOLD}) and Signature Detection...")

    # Simulating 15 network packets
    for i in range(1, 16):

        # Simulation Logic: Assign random IPs and occasional malicious payloads
        if i == 5:
            incoming_ip, payload = "192.168.1.50", "GET /scripts/root.exe" # Malware attempt
        elif i > 10:
            incoming_ip, payload = "172.16.0.10", "Normal traffic" # DoS attempt
        else:
            incoming_ip, payload = f"192.168.1.{random.randint(1, 20)}", "Normal traffic"

        # 1. Whitelist Check
        if incoming_ip in WHITELIST:
            action, reason = "ALLOW", "Whitelisted" #
        
        # 2. Blacklist Check
        elif incoming_ip in blacklist:
            action, reason = "BLOCK", "Blacklisted"

        # 3. Signature Detection Check
        elif is_malicious_payload(payload):
            action, reason = "BLOCK", "Malicious Signature (Nimda)"
            blacklist.add(incoming_ip) #

        # 4. DoS Protection 
        else:
            packet_counts[incoming_ip] += 1
            if packet_counts[incoming_ip] > THRESHOLD:
                action, reason = "BLOCK", "DoS Attack Detected"
                blacklist.add(incoming_ip)
            else:
                action, reason = "ALLOW", ""

        # Log and Print
        log_event(incoming_ip, action, reason)
        status = "?" if action == "BLOCK" else "?"
        print(f"[{i:02d}] {incoming_ip} -> {status} {action} {f'({reason})' if reason else ''}")
        time.sleep(0.3)

if __name__ == "__main__":
    run_firewall()