# Advanced Subdomain Enumeration Framework

<p align="center">
  <img src="./banner_anim.gif" alt="Pradyumn Tiware Nexus" style="max-width:100%; height:auto;" />
</p>

> **Advanced Subdomain Enumeration Framework** — Passive-first, modular recon tool with optional API integrations (VirusTotal, Shodan, urlscan.io, SecurityTrails). Use responsibly — only against targets you own or have explicit permission to test.

---

## Features Overview

* Subdomain Enumeration (Passive + Optional Active)
* DNS Resolution
* HTTP Probing (optional)
* API Integrations (VirusTotal, Shodan, urlscan.io, SecurityTrails)
* JS File Discovery (planned module)
* Endpoint Extraction (planned)
* File Discovery (planned)

---

## Quick index

* ✅ Installation (clone, venv, deps)
* ✅ Full command reference (all flags & examples)
* ✅ How to permanently add API keys (Linux/macOS/Windows)
* ✅ Docker & Makefile snippets
* ✅ Troubleshooting & tips

---

## 1. Installation (step-by-step)

```bash
# 1) Clone repository
git clone https://github.com/PradyumnTiwareNexus/Advanced-Subdomain-Enumeration-Framework.git
cd Advanced-Subdomain-Enumeration-Framework

# 2) Create a Python virtual environment (recommended)
python3 -m venv venv

# 3) Activate the venv
# Bash / Zsh / WSL:
source venv/bin/activate

# 4) Create requirements.txt (already provided in repo or create if missing)
cat > requirements.txt <<'EOF'
aiohttp
dnspython
EOF

# 5) Upgrade pip and install deps
pip install --upgrade pip
pip install -r requirements.txt

# 6) Show help to verify everything works
python3 allinone_recon_with_keys.py -h
```

When you're done running the tool, leave the venv with:

```bash
deactivate
```

---

## 2. Command Reference & Examples (All Tools)

### **A) Subdomain Enumeration (main tool)**

```
python3 allinone_recon_with_keys.py -d example.com -o results.json
```

### **B) Live Subdomain Probe (HTTP status check)**

```
python3 allinone_recon_with_keys.py -d example.com --http-probe -o live.json
```

### **C) Bruteforce Subdomains**

```
python3 allinone_recon_with_keys.py -d example.com --bruteforce wordlist.txt -o brute.json
```

### **D) API‑powered Deep Enumeration**

```
python3 allinone_recon_with_keys.py -d example.com \
  --vt-key $VT_API_KEY \
  --shodan-key $SHODAN_API_KEY \
  --urlscan-key $URLSCAN_API_KEY \
  --strails-key $STRAILS_API_KEY \
  -o deep.json
```

### **E) Full Pipeline (Recommended)**

```
python3 allinone_recon_with_keys.py -d example.com \
  --bruteforce wordlist.txt \
  --http-probe \
  --vt-key $VT_API_KEY \
  --shodan-key $SHODAN_API_KEY \
  -o final.json
```

---

## Output Structure (What you get)

Tool output comes in structured JSON or CSV.

### **1. candidates**

All discovered subdomains (CRT.SH + APIs + Bruteforce).

### **2. resolved**

Only those which have DNS A‑record → real existing hosts.
Example:

```
"resolved": {
  "api.example.com": "103.21.244.15",
  "dev.example.com": "192.168.10.2"
}
```

### **3. unresolved**

Generated or discovered but no DNS record.

### **4. http** (only if `--http-probe` enabled)

Shows:

* HTTP status
* Final URL after redirect
* Live or dead

Example:

```
"http": {
  "api.example.com": {
    "http_ok": true,
    "status": 200,
    "url": "https://api.example.com/"
  }
}
```

### **5. Future Modules (coming updates)**

* **JavaScript Extraction** → finds JS files of live subdomains
* **Secret Scanner** → API keys, tokens, credentials inside JS
* **File Finder** → sitemap.xml, robots.txt, backup files
* **Archive Miner** → wayback + archive.org URLs

```
usage: allinone_recon_with_keys.py -d DOMAIN [-o OUTPUT] [--bruteforce WORDLIST]
                                     [--http-probe] [--concurrency N]
                                     [--vt-key KEY] [--shodan-key KEY]
                                     [--urlscan-key KEY] [--strails-key KEY]
```

### Minimal (passive) run — CRT.SH + DNS

```bash
python3 allinone_recon_with_keys.py -d example.com -o results.json
```

### Enable HTTP probing (active; get permission first)

```bash
python3 allinone_recon_with_keys.py -d example.com --http-probe -o results.json
```

### Bruteforce candidate generation from wordlist (DNS resolve only)

```bash
python3 allinone_recon_with_keys.py -d example.com --bruteforce wordlist.txt -o results.json
```

### Output CSV instead of JSON

```bash
python3 allinone_recon_with_keys.py -d example.com -o results.csv
```

### Use API keys on the command line

```bash
python3 allinone_recon_with_keys.py -d example.com \
  --vt-key YOUR_VT_KEY \
  --shodan-key YOUR_SHODAN_KEY \
  --urlscan-key YOUR_URLSCAN_KEY \
  --strails-key YOUR_SECURITYTRAILS_KEY \
  -o results.json
```

### Use environment variables (recommended)

```bash
export VT_API_KEY="YOUR_VT_KEY"
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
export URLSCAN_API_KEY="YOUR_URLSCAN_KEY"
export STRAILS_API_KEY="YOUR_SECURITYTRAILS_KEY"

python3 allinone_recon_with_keys.py -d example.com -o results.json
```

### Example: full pipeline (bruteforce + API keys + http probe)

```bash
export VT_API_KEY="..."
export SHODAN_API_KEY="..."
export URLSCAN_API_KEY="..."
export STRAILS_API_KEY="..."

python3 allinone_recon_with_keys.py -d example.com --bruteforce wordlist.txt --http-probe -o final_results.json
```

---

## 3. How to persist API keys permanently (Linux/macOS)

### Option A — Add to `~/.bashrc` or `~/.zshrc` (simple)

Append these lines (replace keys) to `~/.bashrc` or `~/.zshrc`:

```bash
# Add API keys for All-in-One Recon (reload or open new shell to use)
export VT_API_KEY="YOUR_VT_KEY"
export SHODAN_API_KEY="YOUR_SHODAN_API_KEY"
export URLSCAN_API_KEY="YOUR_URLSCAN_KEY"
export STRAILS_API_KEY="YOUR_SECURITYTRAILS_KEY"
```

Then reload the file:

```bash
source ~/.bashrc    # or source ~/.zshrc
```

### Option B — Use `~/.profile` or `/etc/environment` (system-wide)

* `~/.profile` works for login shells. Add the same `export` lines.
* `/etc/environment` can be used for system-wide persistent vars (requires sudo). Format differs: `KEY=value` (no `export`).

**Note:** Storing secrets in plain text is convenient but not the most secure. Consider `direnv`, `pass`, or storing secrets in a password manager or CI secrets store.

### Option C — `direnv` (per-project, safer)

Install `direnv` and add a `.envrc` to the project folder:

```bash
# .envrc (in project root)
export VT_API_KEY="YOUR_VT_KEY"
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
export URLSCAN_API_KEY="YOUR_URLSCAN_KEY"
export STRAILS_API_KEY="YOUR_SECURITYTRAILS_KEY"
```

Then run:

```bash
direnv allow
```

`direnv` loads local env vars only when you `cd` into the project — safer for secrets.

### Option D — Windows PowerShell (persist using `setx`)

Run PowerShell as Administrator:

```powershell
setx VT_API_KEY "YOUR_VT_KEY"
setx SHODAN_API_KEY "YOUR_SHODAN_KEY"
setx URLSCAN_API_KEY "YOUR_URLSCAN_KEY"
setx STRAILS_API_KEY "YOUR_SECURITYTRAILS_KEY"
```

Then open a new PowerShell window to use them.

---

## 4. Troubleshooting & common errors

* `externally-managed-environment` or `permission` error when using `pip`:

  * Make sure you created & activated a venv (`python3 -m venv venv` then `source venv/bin/activate`).
  * Do **not** run `pip install` system-wide on distro-managed Python unless you know what you're doing.

* `ModuleNotFoundError: No module named 'aiohttp'`:

  * Activate venv and `pip install -r requirements.txt`.

* API calls returning `401` / `403`:

  * Check your API key, account plan and rate limits.
  * Some APIs require different header keys (tool tries common header types); double-check provider docs.

* Too many DNS requests or HTTP probes:

  * Reduce `--concurrency` to a smaller number.
  * Use `--http-probe` only with explicit permission.

---

## 5. Optional: Dockerfile (quick reproducible environment)

```dockerfile
# Dockerfile (example)
FROM python:3.13-slim
WORKDIR /app
COPY . /app
RUN pip install --upgrade pip && pip install -r requirements.txt
ENTRYPOINT ["python3", "allinone_recon_with_keys.py"]
# Usage:
# docker build -t allinone-recon .
# docker run --rm -e VT_API_KEY=... allinone-recon -d example.com -o results.json
```

---

## 6. Optional: Makefile (convenience)

```makefile
venv:
	python3 -m venv venv

activate:
	source venv/bin/activate

install:
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt

run:
	./venv/bin/python3 allinone_recon_with_keys.py -d example.com -o results.json
```

Run `make venv install run` as a quick flow.

---

## 7. Security & Responsible Use

* Only scan domains you own or have explicit written permission to test. Unauthorized scanning may be illegal.
* Keep your API keys private. Do **not** push keys to public repositories.
* Use `direnv`, `.env` ignored by git, or CI secret stores for automation.

---

## 8. Contributing & PRs

PRs are welcome. If you add support for more APIs, please:

* Add tests (if possible)
* Add docs in this README
* Keep the default behavior passive-first

---
