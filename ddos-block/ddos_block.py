import subprocess
import os
import platform

def run_command(command):
    """Hàm trợ giúp để chạy lệnh hệ thống một cách an toàn."""
    try:
        subprocess.run(command, check=True, shell=False, capture_output=True, text=True)
        return True, ""
    except subprocess.CalledProcessError as e:
        print(f"Error executing: {' '.join(command)}\n{e.stderr}")
        return False, e.stderr

def block_ip(ip):
    """Chặn IP bằng firewall phù hợp với hệ điều hành."""
    print(f"BLOCKING: Attempting to block IP {ip}")
    system = platform.system()

    if system == "Windows":
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"
        ]
    else:
        command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    success, _ = run_command(command)
    if success:
        print(f"SUCCESS: Blocked {ip}")
    return success

def unblock_ip(ip):
    """Bỏ chặn IP bằng firewall phù hợp với hệ điều hành."""
    print(f"UNBLOCKING: Attempting to unblock IP {ip}")
    system = platform.system()

    if system == "Windows":
        command = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=Block_{ip}"
        ]
    else:
        command = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

    success, _ = run_command(command)
    if success:
        print(f"SUCCESS: Unblocked {ip}")
    return success
