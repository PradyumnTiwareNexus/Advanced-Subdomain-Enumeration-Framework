#!/usr/bin/env python3
"""
allinone_recon_with_keys.py
Advanced Subdomain Enumeration Framework (passive-first) with optional API integrations.

Usage examples:
    python allinone_recon_with_keys.py -d example.com -o results.json
    python allinone_recon_with_keys.py -d example.com --vt-key YOUR_VT_KEY --shodan-key YOUR_SHODAN_KEY --http-probe

Environment variables (alternative to CLI flags):
    VT_API_KEY, SHODAN_API_KEY, URLSCAN_API_KEY, STRAILS_API_KEY

Notes / Safety:
 - By default this tool uses passive sources (crt.sh) and DNS resolution.
 - HTTP probing and bruteforce are optional and disabled unless you pass the flags.
 - ONLY run against domains you own or have explicit permission to test.
 - API integrations are optional and will only run if you supply your own API keys.
"""

import argparse
import asyncio
import aiohttp
import csv
import json
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List, Set, Dict, Optional
from urllib.parse import quote_plus, urlencode

# ------------- Config / Defaults -------------
CRT_SH_URL = "https://crt.sh/?q={query}&output=json"
DEFAULT_CONCURRENCY = 30
DNS_THREADPOOL = 50
HTTP_TIMEOUT = 10
UA = "AllInOneRecon/1.0 (+https://example.com/)"

# ------------- Helpers -------------
def normalize_domain(domain: str) -> str:
    return domain.strip().lower().lstrip("*.")  # remove wildcard prefix if present

def unique_preserve_order(seq):
    seen = set()
    out = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out

# ------------- Passive Sources -------------
async def fetch_crtsh(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    q = f"%.{domain}"
    url = CRT_SH_URL.format(query=quote_plus(q))
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT) as resp:
            if resp.status != 200:
                print(f"[crt.sh] non-200 status: {resp.status}", file=sys.stderr)
                return set()
            text = await resp.text()
            try:
                arr = json.loads(text)
            except Exception:
                # fallback to regex parsing
                arr = []
            hosts = set()
            for entry in arr:
                nv = entry.get("name_value") or entry.get("common_name") or ""
                for part in nv.splitlines():
                    part = part.strip()
                    if part:
                        part = part.lstrip("*.")
                        if part.endswith(domain):
                            hosts.add(part.lower())
            return hosts
    except Exception as e:
        print(f"[crt.sh] exception: {e}", file=sys.stderr)
        return set()

# ------------- Third-party API integrations (optional) -------------
# All of these functions are defensive: if API structure differs or request fails, they return empty set.

async def fetch_virustotal(domain: str, api_key: str, session: aiohttp.ClientSession) -> Set[str]:
    """
    VirusTotal v3 - get domain subdomains.
    Requires: API key (v3). Header: Authorization: Bearer <key>
    Endpoint used: /api/v3/domains/{domain}/subdomains (best-effort)
    Note: VT API limits & tiers vary; this is an optional best-effort integration.
    """
    out = set()
    if not api_key:
        return out
    headers = {"User-Agent": UA, "x-apikey": api_key, "Accept": "application/json"}
    # Some VT accounts use Bearer token (Authorization) others use x-apikey; try both patterns.
    urls_to_try = [
        f"https://www.virustotal.com/api/v3/domains/{quote_plus(domain)}/subdomains",
        f"https://www.virustotal.com/api/v3/domains/{quote_plus(domain)}"
    ]
    for url in urls_to_try:
        try:
            async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT) as resp:
                if resp.status != 200:
                    # try alternative header style
                    headers_alt = {"User-Agent": UA, "Authorization": f"Bearer {api_key}", "Accept": "application/json"}
                    async with session.get(url, headers=headers_alt, timeout=HTTP_TIMEOUT) as r2:
                        if r2.status != 200:
                            continue
                        data = await r2.json()
                        # handle below
                        resp_json = data
                else:
                    resp_json = await resp.json()
            # Parse possible places for subdomains
            # v3 /domains/{domain}/subdomains typically returns data: [{ "id": "sub.example.com", ...}, ...]
            if isinstance(resp_json, dict):
                if "data" in resp_json:
                    for item in resp_json.get("data", []):
                        # id sometimes has domain or subdomain
                        _id = item.get("id") or ""
                        if isinstance(_id, str) and _id.endswith(domain):
                            out.add(_id.lower())
                        # sometimes attributes/name exists
                        attrs = item.get("attributes") or {}
                        name = attrs.get("hostname") or attrs.get("name") or attrs.get("value")
                        if name and isinstance(name, str) and name.endswith(domain):
                            out.add(name.lower())
                # fallback: maybe relationships or nested
            break
        except Exception:
            continue
    return out

async def fetch_shodan(domain: str, api_key: str, session: aiohttp.ClientSession) -> Set[str]:
    """
    Shodan DNS/domain endpoint (best-effort):
    Example endpoint: https://api.shodan.io/dns/domain/{domain}?key={api_key}
    Returns JSON with 'subdomains' key in many cases.
    """
    out = set()
    if not api_key:
        return out
    url = f"https://api.shodan.io/dns/domain/{quote_plus(domain)}?key={quote_plus(api_key)}"
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": UA}) as resp:
            if resp.status != 200:
                return out
            j = await resp.json()
            # expected structure: { "domain": "example.com", "subdomains": ["a","b"], ... }
            if isinstance(j, dict):
                if "subdomains" in j and isinstance(j["subdomains"], list):
                    for s in j["subdomains"]:
                        s2 = f"{s}.{domain}" if not s.endswith(domain) else s
                        out.add(s2.lower())
                # sometimes 'data' or 'hosts' might contain hostnames
                if "data" in j and isinstance(j["data"], list):
                    for it in j["data"]:
                        name = it.get("hostnames") or it.get("hostname")
                        if name:
                            if isinstance(name, list):
                                for h in name:
                                    if h.endswith(domain):
                                        out.add(h.lower())
                            elif isinstance(name, str):
                                if name.endswith(domain):
                                    out.add(name.lower())
    except Exception as e:
        # print(f"[shodan] exception: {e}", file=sys.stderr)
        pass
    return out

async def fetch_urlscan(domain: str, api_key: str, session: aiohttp.ClientSession) -> Set[str]:
    """
    urlscan.io search API - uses query like 'domain:example.com'
    API docs: https://urlscan.io/docs/api/
    Header: API-Key: <key>
    """
    out = set()
    if not api_key:
        return out
    # Use search endpoint; note paging & rate limits exist. We'll fetch first page only.
    q = f"domain:{domain}"
    params = {"q": q}
    url = "https://urlscan.io/api/v1/search/?" + urlencode(params)
    headers = {"User-Agent": UA, "API-Key": api_key}
    try:
        async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT) as resp:
            if resp.status != 200:
                return out
            j = await resp.json()
            # urlscan returns 'results': list of entries with 'task' and 'page' fields; page.domain or page.url may contain host
            if isinstance(j, dict):
                results = j.get("results") or j.get("results")
                if isinstance(results, list):
                    for r in results:
                        page = r.get("page") or {}
                        host = page.get("domain") or page.get("url") or page.get("domainName")
                        if host:
                            # extract hostname
                            try:
                                # page.url might be full url like https://sub.example.com/...
                                from urllib.parse import urlparse
                                parsed = urlparse(host)
                                hostname = parsed.hostname or host
                            except Exception:
                                hostname = host
                            if hostname and hostname.endswith(domain):
                                out.add(hostname.lower())
    except Exception:
        pass
    return out

async def fetch_securitytrails(domain: str, api_key: str, session: aiohttp.ClientSession) -> Set[str]:
    """
    SecurityTrails API (best-effort).
    Endpoint example: https://api.securitytrails.com/v1/domain/{domain}/subdomains
    Header: APIKEY: <key> or Authorization: Bearer <key> depending on account.
    """
    out = set()
    if not api_key:
        return out
    url = f"https://api.securitytrails.com/v1/domain/{quote_plus(domain)}/subdomains"
    headers = {"User-Agent": UA, "APIKEY": api_key}
    try:
        async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT) as resp:
            if resp.status != 200:
                # try bearer
                headers2 = {"User-Agent": UA, "Authorization": f"Bearer {api_key}"}
                async with session.get(url, headers=headers2, timeout=HTTP_TIMEOUT) as r2:
                    if r2.status != 200:
                        return out
                    j = await r2.json()
            else:
                j = await resp.json()
            # expected j like {"subdomains": ["a","b"], ...}
            if isinstance(j, dict) and "subdomains" in j:
                for s in j["subdomains"]:
                    s2 = f"{s}.{domain}" if not s.endswith(domain) else s
                    out.add(s2.lower())
    except Exception:
        pass
    return out

# ------------- Brute force (optional) -------------
def load_wordlist(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return data

def generate_bruteforce(domain: str, words: List[str]) -> List[str]:
    out = []
    for w in words:
        candidate = f"{w}.{domain}"
        out.append(candidate)
    return out

# ------------- DNS resolution & HTTP probing -------------
def resolve_host(host: str) -> Optional[str]:
    try:
        addr = socket.gethostbyname(host)
        return addr
    except Exception:
        return None

async def resolve_hosts_concurrent(hosts: List[str], concurrency: int = DNS_THREADPOOL) -> Dict[str, Optional[str]]:
    loop = asyncio.get_event_loop()
    results: Dict[str, Optional[str]] = {}
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        tasks = []
        for h in hosts:
            tasks.append(loop.run_in_executor(pool, resolve_host, h))
        completed = await asyncio.gather(*tasks)
        for h, r in zip(hosts, completed):
            results[h] = r
    return results

async def http_probe_hosts(hosts: List[str], concurrency: int = 20) -> Dict[str, Dict]:
    sem = asyncio.Semaphore(concurrency)
    out = {}

    async def probe_one(h):
        async with sem:
            result = {"http_ok": False, "status": None, "url": None}
            for proto in ("https://", "http://"):
                url = proto + h
                try:
                    # reuse session per request to be polite
                    async with aiohttp.ClientSession(headers={"User-Agent": UA}) as session:
                        async with session.head(url, timeout=HTTP_TIMEOUT, allow_redirects=True) as resp:
                            result["status"] = resp.status
                            result["http_ok"] = 200 <= resp.status < 400
                            result["url"] = str(resp.url)
                            break
                except Exception:
                    continue
            out[h] = result

    tasks = [probe_one(h) for h in hosts]
    await asyncio.gather(*tasks)
    return out

# ------------- Orchestration -------------
async def enumerate_domain(domain: str,
                           bruteforce_wordlist: Optional[str] = None,
                           do_http_probe: bool = False,
                           concurrency: int = DEFAULT_CONCURRENCY,
                           vt_key: Optional[str] = None,
                           shodan_key: Optional[str] = None,
                           urlscan_key: Optional[str] = None,
                           strails_key: Optional[str] = None) -> Dict:
    domain = normalize_domain(domain)
    headers = {"User-Agent": UA}
    async with aiohttp.ClientSession(headers=headers) as session:
        # 1) crt.sh passive enumeration
        print(f"[+] Querying crt.sh for {domain} ...")
        crt_hosts = await fetch_crtsh(domain, session)
        print(f"[+] crt.sh returned {len(crt_hosts)} candidate hostnames")

        # 2) Third-party APIs (if keys provided)
        api_hosts = set()
        if vt_key:
            print("[+] Querying VirusTotal (using provided key) ...")
            vt = await fetch_virustotal(domain, vt_key, session)
            print(f"[+] VirusTotal returned {len(vt)} hosts")
            api_hosts.update(vt)
        if shodan_key:
            print("[+] Querying Shodan (using provided key) ...")
            sh = await fetch_shodan(domain, shodan_key, session)
            print(f"[+] Shodan returned {len(sh)} hosts")
            api_hosts.update(sh)
        if urlscan_key:
            print("[+] Querying urlscan.io (using provided key) ...")
            us = await fetch_urlscan(domain, urlscan_key, session)
            print(f"[+] urlscan returned {len(us)} hosts")
            api_hosts.update(us)
        if strails_key:
            print("[+] Querying SecurityTrails (using provided key) ...")
            st = await fetch_securitytrails(domain, strails_key, session)
            print(f"[+] SecurityTrails returned {len(st)} hosts")
            api_hosts.update(st)

        # 3) Optional wordlist bruteforce (generate candidates only)
        brute_hosts = set()
        if bruteforce_wordlist:
            print(f"[+] Loading wordlist from {bruteforce_wordlist} ...")
            words = load_wordlist(bruteforce_wordlist)
            print(f"[+] Generating {len(words)} bruteforce candidates (non-probing)")
            brute_candidates = generate_bruteforce(domain, words)
            brute_hosts.update(brute_candidates)

        # combine and dedupe
        combined = list(crt_hosts | api_hosts | brute_hosts)
        all_candidates = unique_preserve_order(combined)
        print(f"[+] Total unique candidates: {len(all_candidates)}")

        # 4) DNS resolution (verify which actually resolve)
        print(f"[+] Resolving {len(all_candidates)} hosts (concurrency={concurrency}) ...")
        resolve_map = await resolve_hosts_concurrent(all_candidates, concurrency)
        resolved = {h: ip for h, ip in resolve_map.items() if ip}
        unresolved = [h for h, ip in resolve_map.items() if not ip]
        print(f"[+] Resolved: {len(resolved)}, Unresolved: {len(unresolved)}")

        # 5) Optional HTTP probe (only if requested)
        http_results = {}
        if do_http_probe:
            to_probe = list(resolved.keys())
            print(f"[+] HTTP probing {len(to_probe)} hosts (this performs active requests) ...")
            http_results = await http_probe_hosts(to_probe, concurrency=concurrency)
            print(f"[+] HTTP probing done")

        result = {
            "domain": domain,
            "counts": {
                "candidates": len(all_candidates),
                "resolved": len(resolved),
                "unresolved": len(unresolved)
            },
            "candidates": all_candidates,
            "resolved": resolved,
            "unresolved": unresolved,
            "http": http_results
        }
        return result

# ------------- Output helpers -------------
def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_csv(path: str, data: Dict):
    rows = []
    candidates = data.get("candidates", [])
    resolved = data.get("resolved", {})
    http = data.get("http", {})
    for h in candidates:
        rows.append({
            "host": h,
            "resolved_ip": resolved.get(h, ""),
            "http_status": http.get(h, {}).get("status") if http.get(h) else "",
            "http_url": http.get(h, {}).get("url") if http.get(h) else ""
        })
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "resolved_ip", "http_status", "http_url"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

# ------------- CLI -------------
def build_argparser():
    p = argparse.ArgumentParser(description="All-in-one Subdomain Recon (Passive-first) with optional API keys")
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    p.add_argument("-o", "--output", required=False, default="results.json", help="Output file (json or csv by extension)")
    p.add_argument("--bruteforce", required=False, help="Path to wordlist for optional bruteforce (will not probe by default)")
    p.add_argument("--http-probe", action="store_true", help="Enable HTTP probing (performs active requests) - use with permission")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrency for DNS and HTTP probing")
    # API keys via CLI
    p.add_argument("--vt-key", required=False, help="VirusTotal API key (optional) or set VT_API_KEY env var")
    p.add_argument("--shodan-key", required=False, help="Shodan API key (optional) or set SHODAN_API_KEY env var")
    p.add_argument("--urlscan-key", required=False, help="urlscan.io API key (optional) or set URLSCAN_API_KEY env var")
    p.add_argument("--strails-key", required=False, help="SecurityTrails API key (optional) or set STRAILS_API_KEY env var")
    return p

def main():
    parser = build_argparser()
    args = parser.parse_args()
    domain = args.domain
    out_path = args.output
    bruteforce_wordlist = args.bruteforce
    do_http_probe = args.http_probe
    concurrency = args.concurrency

    # API keys: CLI flag takes precedence, otherwise check env vars
    vt_key = args.vt_key or os.getenv("VT_API_KEY")
    shodan_key = args.shodan_key or os.getenv("SHODAN_API_KEY")
    urlscan_key = args.urlscan_key or os.getenv("URLSCAN_API_KEY")
    strails_key = args.strails_key or os.getenv("STRAILS_API_KEY")

    print("=== All-in-one Recon (Passive-first) with API key support ===")
    print("Reminder: Run this tool only on domains you own or have permission to test.")
    if do_http_probe:
        print("HTTP probing is enabled — you must have permission to perform active requests against the target.")
    # Echo which API keys were detected (not printing actual keys)
    print("API integrations enabled for:", end=" ")
    enabled = []
    if vt_key: enabled.append("VirusTotal")
    if shodan_key: enabled.append("Shodan")
    if urlscan_key: enabled.append("urlscan")
    if strails_key: enabled.append("SecurityTrails")
    print(", ".join(enabled) if enabled else "none")
    print("Starting...")

    res = asyncio.run(enumerate_domain(domain,
                                      bruteforce_wordlist=bruteforce_wordlist,
                                      do_http_probe=do_http_probe,
                                      concurrency=concurrency,
                                      vt_key=vt_key,
                                      shodan_key=shodan_key,
                                      urlscan_key=urlscan_key,
                                      strails_key=strails_key))
    # Save output
    if out_path.endswith(".json"):
        save_json(out_path, res)
        print(f"[+] Results written to {out_path}")
    elif out_path.endswith(".csv"):
        save_csv(out_path, res)
        print(f"[+] Results written to {out_path}")
    else:
        save_json(out_path, res)
        print(f"[+] Results written to {out_path} (json)")

if __name__ == "__main__":
    main()
