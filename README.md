# ScanP - HTB Tmux Automation

A robust, interactive Python script to automate your HackTheBox (HTB) reconnaissance workflow using Tmux.

## Features

- **Smart Session Management**:
  - Creates a Tmux session with 4 dedicated windows: `SCANNING`, `FUZZING`, `SERVICES`, `SHELL`.
  - Sets up a verified 3-pane split layout for optimal visibility.
  - Automatically handles existing sessions (Attach or Kill/Recreate).

- **Interactive Targeting**:
  - Prompts for **OS** (Linux/Windows) and **TLD** (.htb/.vl) to tailor commands.
  - Safely updates `/etc/hosts` with the target IP and hostname.
  - Checks VPN connection (`tun0`) and target reachability (`ping`).

- **OS-Specific Automation**:
  - **Linux Mode**: Pre-configured with `rustscan`, `feroxbuster`, `updog` (file serving), `ligolo` (pivoting), and `nuclei` (vuln scanning).
  - **Windows Mode**: Includes `nxc` for SMB enumeration/user dumping, plus `nuclei` and `updog`.
  - **Customizable**: Distinct command blocks in the script allow easy editing of tools for each OS.

- **Quality of Life**:
  - Auto-creates directory structure: `/htb/<box_name>/www`.
  - Fixes common issues: Prevents text cutting (`send-keys -l`), auto-answers `ligolo` prompts, and clears shells.

## Usage

1.  **Run with Sudo** (required for `/etc/hosts` and interface checks):
    ```bash
    sudo python3 scanp_automation.py
    ```

2.  **Follow Prompts**:
    - Enter **Box Name** (e.g., `interface`)
    - Enter **IP Address** (e.g., `10.129.2.15`)
    - Select **OS**: `l` (Linux) or `w` (Windows)
    - Select **TLD**: `1` (.htb) or `2` (.vl)

3.  **Hacking Time**:
    - The script will attach you to the new session.
    - Commands will auto-execute in their respective panes.

## Requirements

- Python 3
- Tmux
- Tools: `nmap`, `rustscan`, `feroxbuster`, `ligolo-proxy`, `smbserver.py`, `nuclei`, `updog`, `nxc` (NetExec).

## Customization

Edit the `scanp_automation.py` file to modify the `linux_cmds` or `windows_cmds` lists to include your preferred tools and flags.
