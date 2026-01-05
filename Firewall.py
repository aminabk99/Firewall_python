import random
import time

def log_event(ip, action):
    """Logs the firewall activity to a text file for auditing."""
    with open("firewall_log.txt", "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] IP: {ip} - ACTION: {action}\n")

def check_traffic(ip, blacklist):
    """Checks if an IP is in the blacklist."""
    if ip in blacklist:
        return "BLOCK"
    return "ALLOW"

def run_firewall_simulation():
    # Define our 'Bad Actors' list
    blacklist = ["192.168.1.5", "192.168.1.10", "10.0.0.50", "172.16.0.5"]
    
    print("--- Python Firewall Simulator Active ---")
    print(f"Monitoring traffic. Blacklisted IPs: {blacklist}\n")
    
    # Simulate a stream of 10 incoming packets
    for i in range(1, 11):
        # Generate a random IP (occasionally choosing one from the blacklist)
        if random.random() < 0.3:
            incoming_ip = random.choice(blacklist)
        else:
            incoming_ip = f"192.168.1.{random.randint(1, 254)}"
        
        action = check_traffic(incoming_ip, blacklist)
        log_event(incoming_ip, action)
        
        status_symbol = "?" if action == "BLOCK" else "?"
        print(f"Packet {i:02d}: [{incoming_ip}] -> Result: {status_symbol} {action}")
        
        # Small delay to simulate real-time processing
        time.sleep(0.5)

    print("\nSimulation Complete. Check 'firewall_log.txt' for the full history.")

if __name__ == "__main__":
    run_firewall_simulation()
