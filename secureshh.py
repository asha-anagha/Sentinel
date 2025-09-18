import socket
import paramiko
import threading
import sys
import os
import time
import requests
import subprocess

# Valid credentials for testing
valid_credentials = {
    'admin': 'admin',
    'root': 'toor',
    'user': 'password123'
}

# Simulated current working directory
pwd = ["/home"]

# Enhanced fake file system
fake_filesystem = {
    "/home": ["file1.txt", "file2.log", "folder1", "folder2"],
    "/etc": ["passwd", "shadow"],
    "/var/log": ["auth.log", "syslog"],
    "/home/file1.txt": "Welcome to the ShadowSSH Honeypot.\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:/home/user:/bin/bash\n",
}

# Webhook URL (replace with yours)
WEBHOOK_URL = "https://discord.com/api/webhooks/1387444455132627015/AtNVh5ulmoIXjFS0dU7e8uN8UNzwlPYBjYCHdwhNGp5ZktqVxsyoU-w-Hg7VsS9qvSKL"

# Host key generation (persistent)
if os.path.exists("host_key.pem"):
    host_key = paramiko.RSAKey(filename="host_key.pem")
else:
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file("host_key.pem")

# ASCII Logo
def ascii_logo():
    logo = r"""
   _____ ______ _   _ _______ _____ _   _ ______ _      
  / ____|  ____| \ | |__   __|_   _| \ | |  ____| |     
 | (___ | |__  |  \| |  | |    | | |  \| | |__  | |     
  \___ \|  __| | . ` |  | |    | | | . ` |  __| | |     
  ____) | |____| |\  |  | |   _| |_| |\  | |____| |____ 
 |_____/|______|_| \_|  |_|  |_____|_| \_|______|______|
    """
    print(logo)

# Display disclaimer
def disclaimer():
    os.system("cls" if os.name == "nt" else "clear")
    ascii_logo()
    print("\n⚠️  This tool is for EDUCATIONAL PURPOSES ONLY!")
    print("❌ Do NOT use this tool for any illegal activities.")
    print("✅ The developer is NOT responsible for any misuse.\n")
    user_input = input("Do you agree to use this tool responsibly? (Y/N): ").strip().lower()
    if user_input not in ['y', 'yes']:
        print("❌ Access Denied. Exiting...")
        sys.exit()

# Intro
def home_logo():
    os.system("cls" if os.name == "nt" else "clear")
    ascii_logo()
    print(" 🚀 WELCOME TO SENTINEL")
    print(" 💻 DEVELOPED BY ANAGHA\n")
    time.sleep(1)

# Geo info function (with fallback for local IPs)
def get_geo_info(ip):
    try:
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "Local Network Device"
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        country = res.get("country", "Unknown")
        region = res.get("regionName", "")
        city = res.get("city", "")
        isp = res.get("isp", "")
        return f"{city}, {region}, {country} | ISP: {isp}"
    except:
        return "Geo info not available"

# Resolve hostname from IP
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown host"

# Get MAC address using ARP (only works on local LAN)
def get_mac(ip):
    try:
        output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
        for line in output.splitlines():
            if ip in line:
                parts = line.split()
                return parts[1] if len(parts) > 1 else "MAC not found"
        return "MAC not found"
    except:
        return "MAC lookup failed"

# Webhook alert
def send_webhook_alert(message):
    try:
        requests.post(WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[!] Webhook failed: {e}")

# Paramiko SSH Server Interface
class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.client_ip = None

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        geo_info = get_geo_info(self.client_ip)
        if username in valid_credentials and valid_credentials[username] == password:
            msg = f"[+] SUCCESS: {username} logged in with {password} from {self.client_ip} ({geo_info})"
            print(msg)
            send_webhook_alert(msg)
            return paramiko.AUTH_SUCCESSFUL
        msg = f"[-] FAILED: Login attempt {username}/{password} from {self.client_ip} ({geo_info})"
        print(msg)
        send_webhook_alert(msg)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

# Command handlers
def get_pwd():
    return pwd[0]

def list_directory(path):
    return "  ".join(fake_filesystem.get(path, [])) if isinstance(fake_filesystem.get(path), list) else "No such directory"

def read_file(path):
    return fake_filesystem.get(path, "No such file")

def change_directory(cmd):
    global pwd
    parts = cmd.split(" ")
    if len(parts) > 1:
        new_dir = parts[1]
        if new_dir == "..":
            pwd[0] = os.path.dirname(pwd[0])
        else:
            target_path = os.path.normpath(os.path.join(pwd[0], new_dir))
            if target_path in fake_filesystem and isinstance(fake_filesystem[target_path], list):
                pwd[0] = target_path
            else:
                return f"\r\nNo such directory: {new_dir}\r\n$ "
    return f"\r\n$ "

def command_handler(cmd):
    if cmd == "pwd":
        return f"\r\n{get_pwd()} \r\n$ "
    elif cmd == "ls":
        return f"\r\n{list_directory(pwd[0])} \r\n$ "
    elif cmd.startswith("cd"):
        parts = cmd.strip().split()
        if len(parts) == 1:
            return "\r\n$ "
        return change_directory(cmd)
    elif cmd.startswith("cat "):
        parts = cmd.split(" ", 1)
        file_path = os.path.normpath(os.path.join(pwd[0], parts[1])) if len(parts) > 1 else ""
        return f"\r\n{read_file(file_path)} \r\n$ "
    elif cmd in ["clear", "cls"]:
        return "\r\n" + ("\n" * 50) + "$ "
    elif cmd == "whoami":
        return "\r\nroot\r\n$ "
    elif cmd == "ps":
        return "\r\nPID TTY          TIME CMD\n1234 pts/0    00:00:00 bash\n$ "
    elif cmd == "uname -a":
        return "\r\nLinux sentinel 5.15.0-46-generic #49-Ubuntu SMP x86_64 GNU/Linux\r\n$ "
    elif cmd == "":
        return "\r\n$ "
    else:
        return f"\r\n-bash: {cmd}: command not found\r\n$ "

# Handle client connection
def handle_client(client_socket, client_ip):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(host_key)
    server = SSHHoneypot()
    server.client_ip = client_ip

    try:
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            return

        print("[+] Channel opened")
        server.event.wait(10)
        if not server.event.is_set():
            return

        chan.send("Welcome to SHH!\r\n$ ")
        command_buffer = ""
        while True:
            data = chan.recv(1024).decode('utf-8')
            if not data:
                break
            if data in ('\r', '\n'):
                command = command_buffer.strip()
                if command:
                    print(f"Command received: {command}")
                    output = command_handler(command)
                    chan.send(output)
                command_buffer = ""
            else:
                command_buffer += data
                chan.send(data)
    except Exception as e:
        print(f"Socket exception: {e}")
    finally:
        transport.close()

# Start the honeypot
def start_honeypot():
    host = input("Enter your device IP (e.g., 127.0.0.1): ").strip()
    port = 2222
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[+] SSH Honeypot running on {host}:{port}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_ip = addr[0]
            geo_info = get_geo_info(client_ip)
            hostname = resolve_hostname(client_ip)
            mac = get_mac(client_ip)
            print(f"[+] Connection from {client_ip} ({hostname}) | {geo_info} | MAC: {mac}")
            send_webhook_alert(f"🚨 SSH connection attempt from {client_ip} ({hostname}) | {geo_info} | MAC: {mac}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_ip))
            client_thread.start()
    except KeyboardInterrupt:
        print("Exiting...")
        server_socket.close()
        sys.exit()

# Main entry
if __name__ == "__main__":
    disclaimer()
    home_logo()
    start_honeypot()
