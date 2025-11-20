import time
from collections import defaultdict, deque
from scapy.all import IP

def packet_detector(pkt, traffic_data, target_ip, stop_event, capture_all=False):
    """
    Thu thập packet và ghi lại timestamp theo IP nguồn.
    """
    if stop_event.is_set():
        return

    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # Nếu không capture_all thì chỉ bắt packet tới target_ip
    if not capture_all and dst_ip != target_ip:
        return

    traffic_data[src_ip].append(time.time())


def traffic_analyzer(shared_state, safe_block_ip):
    """
    Phân tích traffic theo chu kỳ và phát hiện tấn công.
    """
    print("ANALYZER: Traffic analyzer started.")
    traffic_data = shared_state.traffic_data
    history_data = shared_state.history_data
    attack_logs = shared_state.attack_logs
    stop_event = shared_state.stop_event
    
    TIME_WINDOW = shared_state.TIME_WINDOW
    MULTIPLIER = shared_state.REQUEST_THRESHOLD_MULTIPLIER

    while not stop_event.is_set():

        now = time.time()

        # Tính số request trong TIME_WINDOW
        for ip, timestamps in list(traffic_data.items()):
            recent = [t for t in timestamps if now - t <= TIME_WINDOW]
            traffic_data[ip] = deque(recent, maxlen=len(timestamps))

            count = len(recent)
            history_data[ip].append(count)

            # Ngưỡng động dựa trên trung bình lịch sử
            if len(history_data[ip]) > 5:
                baseline = sum(history_data[ip]) / len(history_data[ip])
            else:
                baseline = 0

            threshold = max(50, baseline * MULTIPLIER)

            if count >= threshold and count > 0:
                msg = f"[ALERT] Suspicious traffic from {ip} -> {count} req (threshold {threshold:.1f})"
                print(msg)
                attack_logs.appendleft(msg)

                safe_block_ip(ip)

        time.sleep(1)
