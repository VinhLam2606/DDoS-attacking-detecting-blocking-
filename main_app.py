import os
import sys
import time
import threading
import logging
import socket
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request, redirect, url_for
from scapy.all import sniff

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(project_root, 'DDoS-Detection'))
sys.path.append(os.path.join(project_root, 'ddos-block'))
sys.path.append(os.path.join(project_root, 'ddos-attack'))

from ddos_detection import traffic_analyzer, packet_detector
from ddos_block import block_ip, unblock_ip
from ddos_attack import simulate_ddos

# --- Config & State ---
logging.basicConfig(filename='ddos_dashboard.log', level=logging.INFO, format='%(asctime)s - %(message)s')

CAPTURE_ALL = True  # True => bắt tất cả IP để debug, False => chỉ target_ip

class Config:
    TIME_WINDOW = 10
    HISTORY_WINDOW = 60
    REQUEST_THRESHOLD_MULTIPLIER = 3
    SIM_NUM_IPS = 1000
    SIM_PACKETS_PER_IP = 50
    SIM_DURATION_PER_IP = 5

TARGET_IP = None
TARGET_URL = None
threads = {"sniffer": None, "analyzer": None, "attack": None}
stop_event = threading.Event()

traffic_data = defaultdict(lambda: deque(maxlen=Config.TIME_WINDOW * 5))
history_data = defaultdict(lambda: deque(maxlen=Config.HISTORY_WINDOW))
attack_logs = deque(maxlen=200)
blocked_ips = set()
defense_enabled = True

class SharedState:
    def __init__(self):
        self.stop_event = stop_event
        self.traffic_data = traffic_data
        self.history_data = history_data
        self.attack_logs = attack_logs
        self.blocked_ips = blocked_ips
        self.TIME_WINDOW = Config.TIME_WINDOW
        self.REQUEST_THRESHOLD_MULTIPLIER = Config.REQUEST_THRESHOLD_MULTIPLIER

shared_state_instance = SharedState()

# --- HTML Templates ---

INDEX_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>DDoS Dashboard - Setup</title><script src="https://cdn.tailwindcss.com"></script><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"><style> body { font-family: 'Inter', sans-serif; } </style></head><body class="bg-gray-900 text-white flex items-center justify-center min-h-screen"><div class="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-xl shadow-lg"><h1 class="text-3xl font-bold text-center text-cyan-400">DDoS Control Dashboard</h1><p class="text-center text-gray-400">Enter a target URL to monitor traffic, simulate attacks, and apply defensive blocking.</p><form action="/start" method="post" class="space-y-6"><div><label for="url" class="text-sm font-medium text-gray-300">Target Website URL</label><input type="text" id="url" name="url" class="mt-1 block w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:ring-cyan-500 focus:border-cyan-500" placeholder="e.g., example.com" required></div><button type="submit" class="w-full px-4 py-2 font-semibold text-white bg-cyan-600 rounded-md hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500 focus:ring-offset-gray-800 transition-colors">Start Monitoring</button></form><p class="text-xs text-center text-gray-500">Disclaimer: For educational purposes only. Requires root/admin privileges.</p></div></body></html>
"""

MONITOR_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>DDoS Dashboard</title><script src="https://cdn.tailwindcss.com"></script><script src="https://cdn.jsdelivr.net/npm/chart.js"></script><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"><style>body { font-family: 'Inter', sans-serif; } .log-entry { animation: fadeIn 0.5s ease-in-out; } @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }</style></head><body class="bg-gray-900 text-white p-4 md:p-8"><div class="max-w-7xl mx-auto">

<header class="flex flex-wrap justify-between items-center mb-6">
  <div>
    <h1 class="text-3xl font-bold text-cyan-400">DDoS Dashboard</h1>
    <p class="text-gray-400">Monitoring & Defending: <strong class="text-cyan-300">{{ target_url }}</strong> ({{ target_ip }})</p>
    <div class="mt-2 flex items-center gap-2">
      <span id="defenseBadge" class="px-2 py-1 text-xs rounded bg-emerald-600">Defense: ON</span>
      <button id="defenseToggle" class="px-3 py-1 text-xs rounded bg-gray-700 hover:bg-gray-600">Toggle</button>
    </div>
  </div>
  <a href="/stop" class="mt-4 md:mt-0 px-4 py-2 font-semibold text-white bg-red-600 rounded-md hover:bg-red-700 transition-colors">Stop & Unblock All</a>
</header>

<main class="grid grid-cols-1 lg:grid-cols-5 gap-6">
  <div class="lg:col-span-3 grid gap-6">
    <div class="bg-gray-800 p-6 rounded-xl shadow-lg">
      <h2 class="text-xl font-semibold mb-4">Live Traffic by Source IP</h2>
      <div class="h-80"><canvas id="trafficChart"></canvas></div>
    </div>
    <div class="bg-gray-800 p-6 rounded-xl shadow-lg">
      <h2 class="text-xl font-semibold mb-4">Detection Log</h2>
      <div id="logContainer" class="space-y-3 h-72 overflow-y-auto pr-2"><p class="text-gray-500">Waiting for events...</p></div>
    </div>
  </div>

  <div class="lg:col-span-2 grid gap-6">
    <div class="bg-gray-800 p-6 rounded-xl shadow-lg">
      <h2 class="text-xl font-semibold mb-4 text-orange-400">Attack Simulation</h2>
      <form action="/attack" method="post" class="space-y-4">
        <p class="text-sm text-gray-400">Launch a simulated DDoS attack against the target to test defenses.</p>
        <button type="submit" id="attackBtn" class="w-full px-4 py-2 font-semibold text-white bg-orange-600 rounded-md hover:bg-orange-700 transition-colors">Launch Test Attack</button>
      </form>
      <p id="attackStatus" class="text-sm text-yellow-400 mt-3"></p>
    </div>

    <div class="bg-gray-800 p-6 rounded-xl shadow-lg">
      <h2 class="text-xl font-semibold mb-4 text-red-400">Blocked IPs</h2>
      <div id="blockedIpContainer" class="space-y-2 h-72 overflow-y-auto pr-2"><p class="text-gray-500">No IPs blocked yet.</p></div>
    </div>
  </div>
</main>

</div>

<script>
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
  type: 'bar',
  data: { labels: [], datasets: [{ label: 'Requests in Time Window', data: [], backgroundColor: 'rgba(22, 163, 224, 0.5)', borderColor: 'rgba(22, 163, 224, 1)', borderWidth: 1 }] },
  options: { responsive: true, maintainAspectRatio: false,
    scales: { y: { beginAtZero: true, ticks: { color: '#d1d5db' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } },
              x: { ticks: { color: '#d1d5db' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } } },
    plugins: { legend: { labels: { color: '#d1d5db' } } } }
});

const logContainer = document.getElementById('logContainer');
const blockedIpContainer = document.getElementById('blockedIpContainer');
const attackStatus = document.getElementById('attackStatus');
const attackBtn = document.getElementById('attackBtn');
const defenseBadge = document.getElementById('defenseBadge');
const defenseToggle = document.getElementById('defenseToggle');

function setDefenseUI(isOn) {
  defenseBadge.textContent = 'Defense: ' + (isOn ? 'ON' : 'OFF');
  defenseBadge.className = 'px-2 py-1 text-xs rounded ' + (isOn ? 'bg-emerald-600' : 'bg-gray-600');
  defenseToggle.textContent = isOn ? 'Disable' : 'Enable';
}

async function toggleDefense() {
  try {
    const res = await fetch('/toggle_defense', { method: 'POST' });
    if (!res.ok) return;
    const data = await res.json();
    setDefenseUI(data.defense_enabled);
  } catch (e) { console.error(e); }
}

defenseToggle.addEventListener('click', (e) => { e.preventDefault(); toggleDefense(); });

async function updateData() {
  try {
    const response = await fetch('/data');
    if (!response.ok) return;
    const data = await response.json();

    // Chart
    trafficChart.data.labels = data.ips;
    trafficChart.data.datasets[0].data = data.counts;
    trafficChart.update();

    // Logs
    if (data.attack_logs && data.attack_logs.length > 0) {
      if (logContainer.querySelector('.text-gray-500')) { logContainer.innerHTML = ''; }
      const existingLogs = new Set(Array.from(logContainer.children).map(p => p.textContent));
      data.attack_logs.forEach(log => {
        if (!existingLogs.has(log)) {
          const p = document.createElement('p');
          p.className = 'p-2 bg-yellow-900/50 rounded-md text-sm log-entry';
          p.textContent = log;
          logContainer.prepend(p);
        }
      });
    }

    // Blocked IPs
    if (data.blocked_ips && data.blocked_ips.length > 0) {
      if (blockedIpContainer.querySelector('.text-gray-500')) { blockedIpContainer.innerHTML = ''; }
      const existingIps = new Set(Array.from(blockedIpContainer.children).map(div => div.dataset.ip));
      data.blocked_ips.forEach(ip => {
        if (!existingIps.has(ip)) {
          const div = document.createElement('div');
          div.dataset.ip = ip;
          div.className = 'flex justify-between items-center p-2 bg-red-900/50 rounded-md text-sm log-entry';
          div.innerHTML = `<span>${ip}</span><a href="/unblock/${ip}" class="px-2 py-1 text-xs bg-gray-600 hover:bg-gray-500 rounded">Unblock</a>`;
          blockedIpContainer.prepend(div);
        }
      });
    } else {
      if (!blockedIpContainer.querySelector('.text-gray-500')) {
        blockedIpContainer.innerHTML = '<p class="text-gray-500">No IPs blocked yet.</p>';
      }
    }

    // Attack status
    attackStatus.textContent = data.attack_status;
    attackBtn.disabled = data.attack_status.includes("in progress");

    // Defense status
    setDefenseUI(data.defense_enabled);

  } catch (error) {
    console.error("Error fetching data:", error);
  }
}
setInterval(updateData, 2000);
updateData();
</script>

</body></html>
"""

# --- Các hàm lõi và điều khiển luồng ---

def setup_templates():
    if not os.path.exists('templates'):
        os.makedirs('templates')
    with open('templates/index.html', 'w', encoding='utf-8') as f: f.write(INDEX_HTML)
    with open('templates/monitor.html', 'w', encoding='utf-8') as f: f.write(MONITOR_HTML)

def unblock_all_ips():
    """Bỏ chặn tất cả IP trong danh sách."""
    print("UNBLOCKING: Clearing all blocked IPs.")
    # Chuyển set thành list để tránh lỗi thay đổi kích thước trong khi lặp
    for ip in list(blocked_ips):
        if unblock_ip(ip):
            blocked_ips.discard(ip)
            attack_logs.appendleft(f"UNBLOCKED: {ip}")

def safe_block_ip(ip: str):
    """Hàm bao bọc để chặn IP, chỉ hoạt động khi chế độ phòng thủ được bật."""
    global defense_enabled
    if ip in blocked_ips:
        return
        
    if defense_enabled:
        print(f"BLOCKING (defense=ON): Attempting to block {ip}")
        if block_ip(ip):
            blocked_ips.add(ip)
            attack_logs.appendleft(f"BLOCKED: {ip}")
        else:
            attack_logs.appendleft(f"[ERROR] Failed to block {ip}")
    else:
        msg = f"[DEFENSE OFF] Detected suspicious IP {ip}, NOT blocking."
        print(msg)
        attack_logs.appendleft(msg)

# NEW: Hàm vòng lặp cho sniffer để dừng an toàn
def sniffer_loop():
    while not stop_event.is_set():
        try:
            sniff(
                prn=lambda pkt: packet_detector(pkt, traffic_data, TARGET_IP, stop_event, capture_all=CAPTURE_ALL),
                filter=None if CAPTURE_ALL else f"host {TARGET_IP}",
                store=0,
                timeout=1
            )
        except Exception as e:
            logging.error(f"Sniffer error: {e}")
            time.sleep(1)

def start_monitoring_threads():
    """Khởi tạo và bắt đầu các luồng giám sát và phân tích."""
    global TARGET_IP
    if threads["sniffer"] and threads["sniffer"].is_alive():
        return

    stop_event.clear()

    # Analyzer nhận shared_state + safe_block_ip
    threads["analyzer"] = threading.Thread(target=traffic_analyzer, args=(shared_state_instance, safe_block_ip), daemon=True)

    # Sniffer sử dụng vòng lặp an toàn thay vì stop_filter
    threads["sniffer"] = threading.Thread(target=sniffer_loop, daemon=True)

    threads["analyzer"].start()
    threads["sniffer"].start()
    print(f"DETECTION: Started sniffing and analysis for {TARGET_IP}")


# --- Ứng dụng Flask ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    global TARGET_IP, TARGET_URL
    if threads["sniffer"] and threads["sniffer"].is_alive():
        stop()  # Dừng phiên cũ nếu có

    # Xóa dữ liệu cũ
    traffic_data.clear()
    history_data.clear()
    attack_logs.clear()
    unblock_all_ips()

    TARGET_URL = request.form.get('url')
    if not TARGET_URL:
        return "URL is required.", 400
    try:
        # Loại bỏ tiền tố http/https để lấy tên miền
        clean_url = TARGET_URL.replace("https://", "").replace("http://", "").split('/')[0]
        TARGET_IP = socket.gethostbyname(clean_url)
        print(f"Resolved {clean_url} to {TARGET_IP}")
    except socket.gaierror:
        return f"Could not resolve IP for the given domain: {TARGET_URL}", 400

    start_monitoring_threads()
    return redirect(url_for('monitor'))

@app.route('/monitor')
def monitor():
    if not TARGET_IP:
        return redirect(url_for('index'))
    return render_template('monitor.html', target_url=TARGET_URL, target_ip=TARGET_IP)

@app.route('/data')
def get_data():
    if not TARGET_IP:
        return jsonify({"ips": [], "counts": [], "attack_logs": [], "blocked_ips": [], "attack_status": "Idle", "defense_enabled": defense_enabled})

    current_time = time.time()
    sorted_traffic = sorted(
        traffic_data.items(),
        key=lambda item: len([ts for ts in item[1] if current_time - ts <= Config.TIME_WINDOW]),
        reverse=True
    )
    top_traffic = sorted_traffic[:20]
    ips = [ip for ip, timestamps in top_traffic]
    counts = [len([ts for ts in timestamps if current_time - ts <= Config.TIME_WINDOW]) for ip, timestamps in top_traffic]

    attack_status = "Idle"
    if threads["attack"] and threads["attack"].is_alive():
        attack_status = "Attack in progress..."

    return jsonify({
        "ips": ips,
        "counts": counts,
        "attack_logs": list(attack_logs),
        "blocked_ips": list(blocked_ips),
        "attack_status": attack_status,
        "defense_enabled": defense_enabled
    })

@app.route('/attack', methods=['POST'])
def attack():
    global TARGET_IP
    if TARGET_IP and (not threads["attack"] or not threads["attack"].is_alive()):
        print("ATTACK: Launching simulation thread...")
        threads["attack"] = threading.Thread(target=simulate_ddos, args=(
            TARGET_IP,
            Config.SIM_NUM_IPS,
            Config.SIM_PACKETS_PER_IP,
            stop_event
        ), daemon=True)
        threads["attack"].start()
    return redirect(url_for('monitor'))

@app.route('/toggle_defense', methods=['POST'])
def toggle_defense():
    global defense_enabled
    defense_enabled = not defense_enabled
    state = "ENABLED" if defense_enabled else "DISABLED"
    attack_logs.appendleft(f"DEFENSE {state}")
    print(f"DEFENSE {state}")

    if not defense_enabled:
        unblock_all_ips()  # bỏ chặn tất cả IP khi tắt defense

    return jsonify({"defense_enabled": defense_enabled})


@app.route('/unblock/<ip>')
def unblock(ip):
    if unblock_ip(ip):
        blocked_ips.discard(ip)
        attack_logs.appendleft(f"UNBLOCKED: {ip}")
    else:
        attack_logs.appendleft(f"[ERROR] Failed to unblock {ip}")
    return redirect(url_for('monitor'))

@app.route('/stop')
def stop():
    global TARGET_IP, TARGET_URL
    print("STOP: Stop event set by user.")
    stop_event.set()

    for thread_name in list(threads.keys()):
        thread = threads.get(thread_name)
        if thread and thread.is_alive():
            try:
                thread.join(timeout=2)
            except RuntimeError as e:
                print(f"Error joining thread {thread_name}: {e}")
        threads[thread_name] = None

    unblock_all_ips()

    TARGET_IP = None
    TARGET_URL = None
    print("MONITORING STOPPED. All IPs unblocked.")
    return redirect(url_for('index'))

def has_admin_privileges():
    """Kiểm tra quyền admin/root."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

if __name__ == "__main__":
    if not has_admin_privileges():
        print("❌ ERROR: This script requires root/administrator privileges for packet sniffing and firewall modification.")
        print("Please run it with 'sudo' (on Linux/macOS) or as an Administrator (on Windows).")
    else:
        print("✅ Script running with sufficient privileges.")
        setup_templates()
        print("🌍 Web interface is available at http://127.0.0.1:5000")
        app.run(host='0.0.0.0', port=5000)