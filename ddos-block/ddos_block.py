import argparse
import subprocess
import os
import time
from collections import defaultdict
from scapy.all import sniff, IP

# === CONFIG ===
REQUEST_THRESHOLD = 20   # requests per second before blocking
INTERFACE = "eth0"       # network interface to monitor

def block_ip(ip, test_mode=False):
    if test_mode:
        print(f"[TEST] Blocking IP {ip}")
    else:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"[REAL] Blocked IP {ip} using iptables")
        except Exception as e:
            print(f"[ERROR] Failed to block {ip}: {e}")

def ddos_block(target_ip, test_mode=False, threshold=REQUEST_THRESHOLD):
    if not test_mode and os.geteuid() != 0:
        print("[ERROR] This script requires root privileges. Run with sudo.")
        exit(1)

    print(f"Monitoring incoming traffic to {target_ip} on interface {INTERFACE}... (CTRL+C to stop)")
    ip_request_count = defaultdict(int)
    blocked_ips = {}
    
    def packet_callback(packet):
        if packet.haslayer(IP) and packet[IP].dst == target_ip:
            src_ip = packet[IP].src
            if src_ip not in blocked_ips:  # Chỉ đếm và hiển thị nếu chưa bị chặn
                ip_request_count[src_ip] += 1

                # Display request
                print(f"Incoming request from {src_ip} to {target_ip} (Count: {ip_request_count[src_ip]})")

                # If exceeds threshold → block
                if ip_request_count[src_ip] > threshold:
                    block_ip(src_ip, test_mode)
                    blocked_ips[src_ip] = time.time()

    try:
        # Start sniffing real traffic
        sniff(iface=INTERFACE, prn=packet_callback, store=False, filter=f"dst host {target_ip}")

    except KeyboardInterrupt:
        print("\nStopping monitoring...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Blocking Script")
    parser.add_argument("target_ip", help="Target IP to monitor/block")
    parser.add_argument("--test", action="store_true", help="Run in test mode (no real firewall changes)")
    parser.add_argument("--threshold", type=int, default=REQUEST_THRESHOLD, help="Request threshold for blocking")
    parser.add_argument("--interface", default=INTERFACE, help="Network interface to monitor (default: eth0)")
    args = parser.parse_args()

    ddos_block(args.target_ip, test_mode=args.test, threshold=args.threshold)