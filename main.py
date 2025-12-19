import tkinter as tk
from tkinter import scrolledtext, messagebox
import nmap
import socket
import threading
import time
from datetime import datetime
import os

known_hosts = set()
monitoring = False

def log(msg):
    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output.insert(tk.END, f"[{t}] {msg}\n")
    output.see(tk.END)
    with open("activity.log", "a") as f:
        f.write(f"[{t}] {msg}\n")

def nmap_exists():
    paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe"
    ]
    return any(os.path.isfile(p) for p in paths)

def get_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ".".join(ip.split(".")[:-1]) + ".0/24"

def get_nmap_scanner():
    paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe"
    ]
    for p in paths:
        if os.path.isfile(p):
            return nmap.PortScanner(nmap_search_path=(p,))
    return None

def scan_devices():
    output.delete(1.0, tk.END)

    output.insert(tk.END, "تم تطويره من المبرمج عبدالرحمن جمال - 2025\n\n")
    if not nmap_exists():
        messagebox.showerror("Error", "Nmap not found in expected paths")
        return
    nm = get_nmap_scanner()
    if nm is None:
        messagebox.showerror("Error", "Failed to initialize Nmap scanner")
        return
    net = get_network()
    log(f"Scanning network {net}")
    nm.scan(hosts=net, arguments="-sn")
    for host in nm.all_hosts():
        hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else "Unknown Hostname"
        log(f"Device detected: {host} | Hostname: {hostname}")
        known_hosts.add(host)
    log("Device scan completed")

def scan_ports():
    if not nmap_exists():
        messagebox.showerror("Error", "Nmap not found in expected paths")
        return
    nm = get_nmap_scanner()
    if nm is None:
        messagebox.showerror("Error", "Failed to initialize Nmap scanner")
        return
    net = get_network()
    log("Port scan started")
    nm.scan(hosts=net, arguments="-p 1-1024 -sS -O --open")
    for host in nm.all_hosts():
        log(f"Host {host}")
        hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else "Unknown Hostname"
        log(f"Hostname: {hostname}")
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            log(f"OS: {nm[host]['osmatch'][0]['name']}")
        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                service = nm[host]['tcp'][port]['name']
                state = nm[host]['tcp'][port]['state']
                log(f"Port {port} | {service} | {state}")
    log("Port scan completed")

def monitor_network():
    global monitoring
    if not nmap_exists():
        messagebox.showerror("Error", "Nmap not found in expected paths")
        return
    monitoring = True
    nm = get_nmap_scanner()
    if nm is None:
        messagebox.showerror("Error", "Failed to initialize Nmap scanner")
        return
    net = get_network()
    log("SOC Monitor Mode started")
    while monitoring:
        nm.scan(hosts=net, arguments="-sn")
        for host in nm.all_hosts():
            if host not in known_hosts:
                known_hosts.add(host)
                hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else "Unknown Hostname"
                log(f"ALERT: New device detected -> {host} | Hostname: {hostname}")
        time.sleep(15)

def start_monitor():
    t = threading.Thread(target=monitor_network, daemon=True)
    t.start()

def stop_monitor():
    global monitoring
    monitoring = False
    log("SOC Monitor Mode stopped")

def copy_output():
    app.clipboard_clear()
    text = output.get(1.0, tk.END)
    app.clipboard_append(text)
    messagebox.showinfo("Copied", "All output copied to clipboard")

app = tk.Tk()
app.title("SecureNet Guardian 2025 - Developed by Abdelrahman Gamal")
app.geometry("980x600")
app.configure(bg="#0d1117")

top = tk.Frame(app, bg="#0d1117")
top.pack(pady=10)

tk.Button(top, text="Scan WiFi Devices", width=22, command=scan_devices, bg="#238636", fg="white").grid(row=0, column=0, padx=5)
tk.Button(top, text="Scan Open Ports + OS", width=22, command=scan_ports, bg="#b62324", fg="white").grid(row=0, column=1, padx=5)
tk.Button(top, text="Start Monitor", width=22, command=start_monitor, bg="#8250df", fg="white").grid(row=0, column=2, padx=5)
tk.Button(top, text="Stop Monitor", width=22, command=stop_monitor, bg="#444c56", fg="white").grid(row=0, column=3, padx=5)
tk.Button(top, text="Copy Output", width=22, command=copy_output, bg="#0969da", fg="white").grid(row=0, column=4, padx=5)

output = scrolledtext.ScrolledText(app, width=115, height=32, bg="#161b22", fg="white", insertbackground="white")
output.pack(pady=10)


output.insert(tk.END, "تم تطويره من المبرمج عبدالرحمن جمال - 2025\n\n")

app.mainloop()
