#!/usr/bin/env python3
"""
scanp_automation.py ??? robust tmux automation for HTB boxes
- 4 windows: SCANNING, FUZZING, SERVICES, SHELL
- Each window has 3 panes with splits (Top, Bottom-Left, Bottom-Right)
- Commands are sent directly without echo wrappers
- Creates /htb/{name} directory structure
- Updates /etc/hosts with strict formatting
- Checks tun0 IP and Pings target
- Auto-attaches to session
"""

import os
import subprocess
import sys
import time
import shutil
from pathlib import Path

# Configuration
SPLIT_DELAY = 0.3
COMMAND_DELAY = 0.7

def check_root():
    if os.geteuid() != 0:
        print("[-] This script requires root privileges (for /etc/hosts and ip commands).")
        print("    Please run with sudo.")
        sys.exit(1)

def run(cmd, check=False, capture=False):
    """Configuration wrapper for subprocess.run"""
    if capture:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return subprocess.run(cmd, check=check)

def check_tun0_interface():
    res = run(["ip", "addr", "show", "tun0"], capture=True)
    for line in res.stdout.splitlines():
        if "inet " in line:
            return line.strip().split()[1].split("/")[0]
    print("[-] tun0 not found or no IP assigned. Are you connected to VPN?")
    sys.exit(1)

def create_directory(name):
    """Creates /htb/{name}/www and returns path object"""
    # Ensure /htb exists
    if not os.path.exists("/htb"):
        try:
            os.makedirs("/htb")
        except OSError as e:
            print(f"[-] Failed to create /htb directory: {e}")
            sys.exit(1)

    path = Path(f"/htb/{name}")
    try:
        (path / "www").mkdir(parents=True, exist_ok=True)
        print(f"[+] Directory created: {path}/www")
    except OSError as e:
        print(f"[-] Failed to create directory {path}: {e}")
        sys.exit(1)
    return path

def ping_host(ip):
    print(f"[i] Waiting for host {ip} to respond to ping...")
    for i in range(1, 16):
        if run(["ping", "-c", "1", "-W", "1", ip], capture=False).returncode == 0:
            print("[+] Host is alive!")
            return
        print(f"[*] Ping attempt {i}/15 failed...")
        time.sleep(1)
    print("[-] Host not responding. Exiting.")
    sys.exit(1)

def append_hosts(box_ip, box_name, tld):
    hosts_path = Path("/etc/hosts")
    try:
        lines = hosts_path.read_text().splitlines()
    except Exception as e:
        print(f"[-] Cannot read /etc/hosts: {e}")
        return

    updated = False
    hostname = f"{box_name}{tld}"
    
    # Clean check for existing entry
    new_lines = []
    for line in lines:
        parts = line.split()
        if parts and parts[0] == box_ip:
            # IP exists, check if hostname is there
            if hostname not in parts:
                line += f" {hostname} {box_name}"
                print(f"[+] Appending {hostname} to existing IP entry.")
            else:
                print(f"[*] {hostname} already mapped to {box_ip}.")
            updated = True
        new_lines.append(line)
    
    if not updated:
        new_lines.append(f"{box_ip}\t{hostname} {box_name}")
        print(f"[+] added {box_ip} -> {hostname}")

    try:
        # Write back cleanly
        content = "\n".join(new_lines)
        if not content.endswith("\n"):
            content += "\n"
            
        with open(hosts_path, "w") as f:
            f.write(content)
            
        print(f"[+] /etc/hosts updated successfully.")
    except Exception as e:
        print(f"[-] Failed to write /etc/hosts: {e}")

def tmux_new_session(session, cwd):
    # Check if session exists
    if run(["tmux", "has-session", "-t", session], capture=True).returncode == 0:
         while True:
            choice = input(f"[-] Session \'{session}\' already exists. Attach (a) or Kill & Recreate (k)? ").lower().strip()
            if choice == "a":
                return True # Attach
            elif choice == "k":
                run(["tmux", "kill-session", "-t", session], check=False)
                break
            else:
                print("Invalid choice. Enter a or k.")

    # Create new session
    # We use -c cwd to set the working directory for the session
    run(["tmux", "new-session", "-d", "-s", session, "-c", cwd], check=True)
    
    # Set options as requested
    run(["tmux", "set-option", "-t", session, "base-index", "1"], check=True)
    run(["tmux", "set-option", "-t", session, "pane-base-index", "1"], check=True)
    run(["tmux", "set-option", "-t", session, "prefix", "C-a"], check=True)
    return False

def create_window(session, name, cwd):
    run(["tmux", "new-window", "-t", session, "-n", name, "-c", cwd], check=True)

def create_3pane_split(session, window):
    """Create 3 panes in window: top/bottom split, then split bottom horizontally"""
    target_window = f"{session}:{window}"
    
    # Pane 1 is default (Top)
    
    # Split top into top/bottom (Pane 2 created at bottom)
    run(["tmux", "split-window", "-v", "-t", f"{target_window}.1"], check=True)
    time.sleep(SPLIT_DELAY)
    
    # Split bottom pane (Pane 2) horizontally (creates Pane 3)
    run(["tmux", "split-window", "-h", "-t", f"{target_window}.2"], check=True)
    time.sleep(SPLIT_DELAY)
    
    # Return pane ids
    out = run(["tmux", "list-panes", "-t", target_window, "-F", "#{pane_index}"], capture=True)
    panes = [f"{target_window}.{line.strip()}" for line in out.stdout.splitlines()]
    return panes  # e.g. [session:window.1, session:window.2, session:window.3]

def send_to_pane(pane_target, command):
    print(f"[*] Sending to {pane_target}: {command[:30]}...")
    # Using -l (literal) prevents tmux from interpreting special chars/keys in the command string
    # This prevents text cutting/wrapping issues (e.g. .htb being split)
    run(["tmux", "send-keys", "-t", pane_target, "-l", command], check=True)
    run(["tmux", "send-keys", "-t", pane_target, "C-m"], check=True)
    time.sleep(COMMAND_DELAY)

def main():
    check_root()
    
    try:
        tun0_ip = check_tun0_interface()
        print(f"[+] tun0 IP: {tun0_ip}")
    except Exception:
        # Fallback if testing locally without VPN, or let user skip
        print("[-] Warning: Failed to get tun0 IP.")
        tun0_ip = "127.0.0.1" 

    box_name = input("[?] Enter box name: ").strip()
    if not box_name:
        print("[-] Box name required.")
        sys.exit(1)
        
    box_path = create_directory(box_name)
    www_dir = box_path / "www"
    
    # Generate shells logic (optional, don\'t crash if missing)
    if shutil.which("gen_lin_rev"):
        os.chdir(str(www_dir))
        print("[*] Generating shells in www/...")
        run(["gen_lin_rev", tun0_ip, "8443"], check=False)
        run(["gen_php_rev", tun0_ip, "8443"], check=False)
    else:
        print("[*] skipping shell generation (gen_lin_rev/gen_php_rev not found)")

    os.chdir(str(box_path))
    
    box_ip = input("[?] Enter box IP: ").strip()
    if not box_ip:
         print("[-] IP required.")
         sys.exit(1)
         
    ping_host(box_ip)
    
    # Architecture / OS
    while True:
        arch_choice = input("[?] Enter Target OS (l for Linux, w for Windows): ").lower().strip()
        if arch_choice in ["l", "w"]:
            target_os = "linux" if arch_choice == "l" else "windows"
            break
        print("Invalid choice. Please enter l or w.")

    # TLD
    while True:
        tld_choice = input("[?] Enter TLD (1 for .htb, 2 for .vl): ").strip()
        if tld_choice == "1":
            tld = ".htb"
            break
        elif tld_choice == "2":
            tld = ".vl"
            break
        print("Invalid choice. Please enter 1 or 2.")

    append_hosts(box_ip, box_name, tld)

    session_name = box_name
    
    # Setup Session
    if tmux_new_session(session_name, str(box_path)) is True:
        # User chose to attach
        print(f"[+] Attaching to existing session \'{session_name}\'...")
        os.execvp("tmux", ["tmux", "attach", "-t", session_name])
        return

    # Create 4 windows
    # Note: SCANNING might be created by default new-session, but we usually get just 1 or zsh.
    # We\'ll rename the first window to SCANNING or create it.
    
    # Rename window 1 to SCANNING
    run(["tmux", "rename-window", "-t", f"{session_name}:1", "SCANNING"], check=False)
    
    windows_to_create = ["FUZZING", "SERVICES", "SHELL"]
    for w in windows_to_create:
        create_window(session_name, w, str(box_path))
        
    all_windows = ["SCANNING", "FUZZING", "SERVICES", "SHELL"]

    # In each window, create 3-pane split
    panes_map = {}
    for w in all_windows:
        panes_map[w] = create_3pane_split(session_name, w)

    # Commands Configuration
    # Define commands based on OS for easy customization
    
    if target_os == 'linux':
        # --- LINUX COMMANDS ---
        print("[*] Loading Linux commands...")
        scanning_cmds = [
            f"rustscan -a {box_ip} -- -sC -sV -o rustscan",
            f"nmap_default {box_ip} -p-",
            f"nmap_udp {box_ip}"
        ]
        fuzzing_cmds = [
            f"vhost {box_name}{tld}",
            f"fuzz_dir http://{box_name}{tld}",
            f"feroxbuster -u http://{box_name}{tld}"
        ]
        services_cmds = [
            f"updog -p 8080",
            f"ip link del ligolo 2>/dev/null; ip tuntap add dev ligolo mode tun user pain; ip link set ligolo up && echo 'N' ; ligolo-proxy -selfcert",
            f"dig {box_name}{tld}"
        ]
        shell_cmds = [
            f"nuclei -u http://{box_name}{tld} -as -s critical,high,medium -fr -rl 20 -timeout 20 -retries 2 -stats -o results.txt",
            "clear",
            "clear"
        ]
    else:
        # --- WINDOWS COMMANDS ---
        print("[*] Loading Windows commands...")
        scanning_cmds = [
            f"rustscan -a {box_ip} -- -sC -sV -o rustscan",
            f"nmap_default {box_ip} -p-",
            f"nmap_udp {box_ip}"
        ]
        fuzzing_cmds = [
            f"vhost {box_name}{tld}",
            f"fuzz_dir http://{box_name}{tld}",
            f"feroxbuster -u http://{box_name}{tld}"
        ]
        services_cmds = [
            f"mkdir -p /htb/{box_name}/share && cd /htb/{box_name} && smbserver.py share ./share -smb2support",
            f"ip link del ligolo 2>/dev/null; ip tuntap add dev ligolo mode tun user pain; ip link set ligolo up && echo 'N' ; ligolo-proxy -selfcert",
            f"dig {box_name}{tld}"
        ]
        shell_cmds = [
            f"sleep 2; ntpdate {box_ip} && nxc smb {box_name} -u 'a' -p '' --shares --users --pass-pol --rid-brute 10000 --log $(pwd)/smb.out; cat smb.out | grep TypeUser | cut -d '\' -f 2 | cut -d ' ' -f 1 > users.txt; cat users.txt",
            f"nuclei -u http://{box_name}{tld} -as -s critical,high,medium -fr -rl 20 -timeout 20 -retries 2 -stats -o results.txt",
            "clear"
        ]

    cmd_map = {
        'SCANNING': scanning_cmds,
        'FUZZING': fuzzing_cmds,
        'SERVICES': services_cmds,
        'SHELL': shell_cmds
    }

    # Send commands
    for w in all_windows:
        panes = panes_map[w]     # e.g. [..1, ..2, ..3]
        cmds = cmd_map[w]        # e.g. [cmd1, cmd2, cmd3]
        
        # Zip them together to matched
        for pane_target, cmd in zip(panes, cmds):
            send_to_pane(pane_target, cmd)

    # Attach session
    print(f"\n[+] Setup complete! Attaching to session \'{session_name}\'...")
    time.sleep(0.5)
    os.execvp("tmux", ["tmux", "attach", "-t", session_name])

if __name__ == "__main__":
    main()
