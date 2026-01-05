import random
import time
from collections import defaultdict

def log_event(ip, action, reason=""):
    """Logs activity with an optional reason (like DoS Detection)."""
    with open("firewall_log.txt", "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        reason_str = f" - REASON: {reason}" if reason else ""
        f.write(f"[{timestamp}] IP: {ip} - ACTION: {action}{reason_str}\n")

def run_firewall_simulation():
    # Setup Initial Rules and Thresholds
    blacklist = set(["192.168.1.5", "10.0.0.50"]) 
    packet_counts = defaultdict(int) # Tracks how many packets each IP sends
    THRESHOLD = 3  # If an IP sends more than 3 packets in this simulation, block it
    
    print("--- Python Firewall & DoS Blocker Active ---")
    print(f"Threshold: {THRESHOLD} packets per session | Initial Blacklist: {blacklist}\n")
    
    # Simulate a larger stream of traffic to test the "flooding" logic
    for i in range(1, 21):
        # We simulate a "Dos Attack" by picking one IP to repeat often
        if i > 10:
            incoming_ip = "172.16.0.10" # This IP will flood the system
        elif random.random() < 0.2:
            incoming_ip = random.choice(list(blacklist))
        else:
            incoming_ip = f"192.168.1.{random.randint(1, 100)}"

        # Check if already blacklisted
        if incoming_ip in blacklist:
            action = "BLOCK"
            reason = "Blacklisted"
        else:
            # Increment count and check for DoS (Rate Limiting)
            packet_counts[incoming_ip] += 1
            
            if packet_counts[incoming_ip] > THRESHOLD:
                action = "BLOCK"
                reason = "DoS Attack Detected"
                blacklist.add(incoming_ip) # Dynamically add to blacklist
            else:
                action = "ALLOW"
                reason = ""

        # Logging and Output
        log_event(incoming_ip, action, reason)
        status_symbol = "?" if action == "BLOCK" else "?"
        msg = f"Packet {i:02d}: [{incoming_ip}] -> {status_symbol} {action}"
        if reason: msg += f" ({reason})"
        print(msg)
        
        time.sleep(0.2)

    print("\nSimulation Complete. Check 'firewall_log.txt' to see the dynamic blocks.")

if __name__ == "__main__":
    run_firewall_simulation()