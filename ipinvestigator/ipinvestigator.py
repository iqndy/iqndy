#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPInvestigator — fiche de renseignement sur une adresse IP.

Entrée  : une adresse IP.
Sortie  : un rapport HTML autonome (capture d'écran incluse) + un JSON brut.

Collecte :
  * scan TCP des ports 80 / 443 (configurable)
  * analyse HTTP/HTTPS : titre, h1, serveur, technologies, cookies,
    en-têtes de sécurité, robots.txt, redirections, certificat TLS
  * capture d'écran de la page (Playwright / Chromium)
  * DNS inverse
  * géolocalisation : bases locales DB-IP lite (.mmdb) + service en ligne
  * RDAP (registre Internet) : bloc, titulaire, contacts abus / NOC
  * PeeringDB : informations sur l'opérateur (ASN)
  * Shodan InternetDB : exposition déjà relevée (ports, hostnames, CVE)

N'utilisez cet outil que sur des adresses que vous êtes autorisé à analyser.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import glob
import gzip
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
import webbrowser

try:
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:  # pragma: no cover
    sys.exit("Le module 'requests' est requis : pip install -r requirements.txt")

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

try:
    import maxminddb
except ImportError:
    maxminddb = None

APP = "IPInvestigator"
VERSION = "1.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")
TIMEOUT = 8

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# ASN / mots-clés d'opérateurs cloud, CDN ou anycast connus
CDN_KEYWORDS = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly",
    "cloudfront": "Amazon CloudFront", "globalaccelerator": "AWS Global Accelerator",
    "awsglobalaccelerator": "AWS Global Accelerator", "incapsula": "Imperva",
    "imperva": "Imperva", "edgecast": "Edgio", "stackpath": "StackPath",
    "sucuri": "Sucuri", "azurefd": "Azure Front Door", "azureedge": "Azure CDN",
    "googleusercontent": "Google Cloud", "1e100.net": "Google",
}
ANYCAST_ASN = {13335: "Cloudflare", 54113: "Fastly", 20940: "Akamai",
               16625: "Akamai", 19551: "Imperva", 209242: "Cloudflare"}
CLOUD_KEYWORDS = ["amazon", "aws", "google", "microsoft", "azure", "ovh",
                  "hetzner", "digitalocean", "linode", "akamai", "scaleway",
                  "oracle", "alibaba", "tencent", "vultr", "contabo", "ionos",
                  "cloudflare", "fastly", "online s.a.s", "leaseweb"]

TECH_PATTERNS = [
    # (nom, où chercher, regex)
    ("WordPress", "html", r"wp-content|wp-includes"),
    ("Joomla", "html", r"/media/jui/|joomla"),
    ("Drupal", "html", r"drupal-settings-json|/sites/default/files"),
    ("Shopify", "html", r"cdn\.shopify\.com"),
    ("Wix", "html", r"static\.wixstatic\.com"),
    ("jQuery", "html", r"jquery[.\-/][\w.\-]*\.js|jquery\.min\.js"),
    ("Bootstrap", "html", r"bootstrap(\.min)?\.(css|js)"),
    ("React", "html", r"data-reactroot|react(-dom)?(\.production)?(\.min)?\.js"),
    ("Next.js", "html", r"__NEXT_DATA__|/_next/static"),
    ("Nuxt", "html", r"__NUXT__|/_nuxt/"),
    ("Vue.js", "html", r"vue(\.runtime)?(\.min)?\.js|data-v-[0-9a-f]{6}"),
    ("Angular", "html", r"ng-version=|angular(\.min)?\.js"),
    ("Font Awesome", "html", r"font-?awesome"),
    ("Google Analytics", "html", r"google-analytics\.com|gtag\(|googletagmanager"),
    ("Google Fonts", "html", r"fonts\.googleapis\.com"),
    ("reCAPTCHA", "html", r"recaptcha"),
    ("Cloudflare", "headers", r"cloudflare|cf-ray"),
    ("nginx", "headers", r"nginx"),
    ("Apache", "headers", r"apache"),
    ("Microsoft IIS", "headers", r"microsoft-iis"),
    ("LiteSpeed", "headers", r"litespeed"),
    ("OpenResty", "headers", r"openresty"),
    ("Caddy", "headers", r"caddy"),
    ("PHP", "headers", r"php"),
    ("ASP.NET", "headers", r"asp\.net"),
    ("Express", "headers", r"express"),
    ("Varnish", "headers", r"varnish"),
    ("Amazon S3", "headers", r"amazons3"),
    ("Amazon ELB", "headers", r"awselb|awsalb"),
    ("PHP", "cookies", r"phpsessid"),
    ("Java", "cookies", r"jsessionid"),
    ("ASP.NET", "cookies", r"asp\.net_sessionid"),
    ("Laravel", "cookies", r"laravel_session|xsrf-token"),
    ("Django", "cookies", r"csrftoken|sessionid"),
    ("Amazon ELB", "cookies", r"awsalb|awselb"),
]


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    print(f"  [*] {msg}", flush=True)


def safe(fn, *a, **kw):
    """Exécute fn et capture les erreurs pour ne jamais bloquer le rapport."""
    try:
        return fn(*a, **kw)
    except Exception as exc:  # noqa: BLE001
        return {"_error": f"{type(exc).__name__}: {exc}"}


def http_json(url: str, timeout: int = TIMEOUT):
    r = requests.get(url, timeout=timeout, headers={"User-Agent": f"{APP}/{VERSION}",
                                                    "Accept": "application/json"})
    if r.status_code == 404:
        return {"_error": "aucune donnée (404)"}
    r.raise_for_status()
    return r.json()


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------- #
# Réseau : scan / DNS
# --------------------------------------------------------------------------- #
def scan_port(ip: str, port: int, timeout: float = 3.0) -> dict:
    start = now_utc()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            ms = (now_utc() - start).total_seconds() * 1000
            return {"port": port, "state": "ouvert", "latency_ms": round(ms, 1)}
    except socket.timeout:
        return {"port": port, "state": "filtré (pas de réponse)"}
    except ConnectionRefusedError:
        return {"port": port, "state": "fermé"}
    except OSError as exc:
        return {"port": port, "state": f"injoignable ({exc.strerror or exc})"}


def reverse_dns(ip: str) -> dict:
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
        return {"hostname": name, "aliases": aliases}
    except (socket.herror, socket.gaierror):
        return {"hostname": None}


# --------------------------------------------------------------------------- #
# Analyse HTTP / HTTPS
# --------------------------------------------------------------------------- #
def tls_info(ip: str, port: int = 443, sni: str | None = None) -> dict:
    info: dict = {}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni or None) as s:
            der = s.getpeercert(binary_form=True)
            info["protocol"] = s.version()
            c = s.cipher()
            info["cipher"] = c[0] if c else None
    info["sha256"] = hashlib.sha256(der).hexdigest().upper()
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        info["not_before"] = nb.strftime("%Y-%m-%d")
        info["not_after"] = na.strftime("%Y-%m-%d")
        info["expired"] = na.replace(tzinfo=dt.timezone.utc) < now_utc()
        info["self_signed"] = cert.subject == cert.issuer
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info["san"] = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            info["san"] = []
    except ImportError:
        info["note"] = "installez 'cryptography' pour le détail du certificat"
    return info


def detect_tech(headers: dict, body: str, cookies: list[str]) -> list[str]:
    hdr_blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    ck_blob = " ".join(cookies).lower()
    body_l = body.lower()
    found: list[str] = []
    for name, where, rx in TECH_PATTERNS:
        blob = {"html": body_l, "headers": hdr_blob, "cookies": ck_blob}[where]
        if re.search(rx, blob) and name not in found:
            found.append(name)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen and gen.group(1) not in found:
        found.append(gen.group(1))
    return found


def parse_html(body: str) -> dict:
    out = {"title": None, "h1": None, "description": None, "links": 0,
           "forms": 0, "password_field": False, "scripts": [], "emails": []}
    if BeautifulSoup:
        soup = BeautifulSoup(body, "html.parser")
        if soup.title and soup.title.string:
            out["title"] = soup.title.string.strip()
        h1 = soup.find("h1")
        if h1:
            out["h1"] = " ".join(h1.get_text(" ").split())[:200]
        d = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
        if d and d.get("content"):
            out["description"] = d["content"].strip()[:300]
        out["links"] = len(soup.find_all("a"))
        out["forms"] = len(soup.find_all("form"))
        out["password_field"] = bool(soup.find("input", attrs={"type": "password"}))
        out["scripts"] = [s["src"] for s in soup.find_all("script", src=True)][:25]
    else:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        out["title"] = html.unescape(m.group(1)).strip() if m else None
        m = re.search(r"<h1[^>]*>(.*?)</h1>", body, re.I | re.S)
        out["h1"] = re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else None
        out["forms"] = len(re.findall(r"<form", body, re.I))
        out["password_field"] = bool(re.search(r'type=["\']?password', body, re.I))
    out["emails"] = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", body)))[:10]
    return out


def http_probe(ip: str, port: int) -> dict:
    scheme = "https" if port in (443, 8443) else "http"
    host = ip if port in (80, 443) else f"{ip}:{port}"
    url = f"{scheme}://{host}/"
    res: dict = {"url": url}
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept-Language": "fr,en;q=0.8"})
    r = s.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    res["status"] = r.status_code
    res["reason"] = r.reason
    res["final_url"] = r.url
    res["redirects"] = [f"{h.status_code} → {h.headers.get('Location', '')}" for h in r.history]
    res["headers"] = dict(r.headers)
    hl = {k.lower(): v for k, v in r.headers.items()}
    res["server"] = hl.get("server")
    res["powered_by"] = hl.get("x-powered-by")
    res["content_type"] = hl.get("content-type")
    res["size"] = len(r.content)
    cookies = []
    for c in r.cookies:
        flags = []
        if c.secure:
            flags.append("Secure")
        if c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"):
            flags.append("HttpOnly")
        ss = c.get_nonstandard_attr("SameSite") or c.get_nonstandard_attr("samesite")
        if ss:
            flags.append(f"SameSite={ss}")
        cookies.append({"name": c.name, "domain": c.domain, "flags": flags})
    # cookies posées pendant les redirections
    for h in r.history:
        for c in h.cookies:
            if c.name not in [x["name"] for x in cookies]:
                cookies.append({"name": c.name, "domain": c.domain, "flags": []})
    res["cookies"] = cookies
    body = r.text if "html" in (res["content_type"] or "html") else ""
    res.update(parse_html(body))
    res["technologies"] = detect_tech(hl, body, [c["name"] for c in cookies])
    res["security_present"] = [h for h in SECURITY_HEADERS if h in hl]
    res["security_missing"] = [h for h in SECURITY_HEADERS if h not in hl]
    # robots.txt / security.txt
    for path, key in (("/robots.txt", "robots"), ("/.well-known/security.txt", "security_txt")):
        try:
            rr = s.get(f"{scheme}://{host}{path}", timeout=TIMEOUT, verify=False)
            ok = rr.status_code == 200 and "<html" not in rr.text[:300].lower()
            res[key] = rr.text[:3000] if ok and rr.text.strip() else None
        except requests.RequestException:
            res[key] = None
    if scheme == "https":
        res["tls"] = safe(tls_info, ip, port)
    return res


def screenshot(url: str, path: str) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"_error": "Playwright non installé (pip install playwright && "
                          "python -m playwright install chromium)"}
    with sync_playwright() as p:
        kw = {}
        exe = os.environ.get("IPINV_CHROMIUM")
        if exe:
            kw["executable_path"] = exe
        browser = p.chromium.launch(**kw)
        try:
            page = browser.new_page(ignore_https_errors=True,
                                    viewport={"width": 1366, "height": 850},
                                    user_agent=UA)
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
            except Exception:  # noqa: BLE001 — on capture quand même ce qui est chargé
                pass
            page.wait_for_timeout(1000)
            page.screenshot(path=path, full_page=False)
        finally:
            browser.close()
    return {"path": path}


# --------------------------------------------------------------------------- #
# Renseignement : géoloc / RDAP / PeeringDB / Shodan
# --------------------------------------------------------------------------- #
def find_mmdb(kind: str) -> str | None:
    files = sorted(glob.glob(os.path.join(DATA_DIR, f"dbip-{kind}-lite*.mmdb")))
    return files[-1] if files else None


def local_geo(ip: str) -> dict:
    out: dict = {}
    if not maxminddb:
        return {"_error": "module maxminddb absent (pip install maxminddb)"}
    city_db, asn_db = find_mmdb("city"), find_mmdb("asn")
    if not city_db and not asn_db:
        return {"_error": "bases DB-IP absentes — lancez : python ipinvestigator.py --update-db"}
    if city_db:
        with maxminddb.open_database(city_db) as db:
            d = db.get(ip) or {}
        nm = lambda x: (x or {}).get("names", {}).get("fr") or (x or {}).get("names", {}).get("en")  # noqa: E731
        subs = d.get("subdivisions") or [{}]
        out["city_db"] = os.path.basename(city_db)
        out["city"] = nm(d.get("city"))
        out["region"] = nm(subs[0])
        out["country"] = nm(d.get("country"))
        out["country_code"] = (d.get("country") or {}).get("iso_code")
        loc = d.get("location") or {}
        out["lat"], out["lon"] = loc.get("latitude"), loc.get("longitude")
    if asn_db:
        with maxminddb.open_database(asn_db) as db:
            d, prefix = db.get_with_prefix_len(ip)
        d = d or {}
        out["asn_db"] = os.path.basename(asn_db)
        out["asn"] = d.get("autonomous_system_number")
        out["as_org"] = d.get("autonomous_system_organization")
        if prefix:
            out["network"] = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    return out


def online_geo(ip: str) -> dict:
    d = http_json(f"https://ipwho.is/{ip}")
    if d.get("success") is False:
        raise RuntimeError(d.get("message", "échec ipwho.is"))
    con = d.get("connection") or {}
    return {"source": "ipwho.is", "city": d.get("city"), "region": d.get("region"),
            "country": d.get("country"), "country_code": d.get("country_code"),
            "lat": d.get("latitude"), "lon": d.get("longitude"),
            "asn": con.get("asn"), "as_org": con.get("org"), "isp": con.get("isp"),
            "domain": con.get("domain"), "timezone": (d.get("timezone") or {}).get("id")}


def _vcard(entity: dict) -> dict:
    out = {"handle": entity.get("handle"), "roles": entity.get("roles", [])}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        key, params, _t, val = item[0], item[1], item[2], item[3]
        if key == "fn":
            out["name"] = val
        elif key == "adr":
            label = params.get("label") if isinstance(params, dict) else None
            if label:
                out["address"] = " ".join(label.split())
            elif isinstance(val, list):
                out["address"] = ", ".join(str(v) for v in val if v)
        elif key == "email":
            out.setdefault("emails", []).append(val)
        elif key == "tel":
            out.setdefault("phones", []).append(str(val).replace("tel:", ""))
    return out


def _flatten_entities(entities: list) -> list[dict]:
    res = []
    for e in entities or []:
        res.append(_vcard(e))
        res.extend(_flatten_entities(e.get("entities")))
    return res


def rdap(ip: str) -> dict:
    d = http_json(f"https://rdap.org/ip/{ip}", timeout=15)
    out = {"handle": d.get("handle"), "name": d.get("name"), "type": d.get("type"),
           "start": d.get("startAddress"), "end": d.get("endAddress"),
           "country": d.get("country"), "parent": d.get("parentHandle"),
           "port43": d.get("port43")}
    cidrs = []
    for c in d.get("cidr0_cidrs", []):
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx:
            cidrs.append(f"{pfx}/{c.get('length')}")
    out["cidr"] = cidrs
    for ev in d.get("events", []):
        a = ev.get("eventAction")
        if a in ("registration", "last changed"):
            out[a.replace(" ", "_")] = (ev.get("eventDate") or "")[:10]
    out["remarks"] = [" ".join(r.get("description", [])) for r in d.get("remarks", [])][:3]
    out["entities"] = _flatten_entities(d.get("entities"))
    links = [l.get("href") for l in d.get("links", []) if l.get("rel") == "self"]
    out["server"] = links[0].split("/")[2] if links else "rdap.org"
    return out


def peeringdb(asn: int) -> dict:
    d = http_json(f"https://www.peeringdb.com/api/net?asn={asn}")
    data = d.get("data") or []
    if not data:
        return {"_error": f"AS{asn} absent de PeeringDB"}
    n = data[0]
    return {"name": n.get("name"), "aka": n.get("aka"), "type": n.get("info_type"),
            "scope": n.get("info_scope"), "website": n.get("website"),
            "traffic": n.get("info_traffic"), "policy": n.get("policy_general"),
            "irr_as_set": n.get("irr_as_set"), "prefixes4": n.get("info_prefixes4"),
            "prefixes6": n.get("info_prefixes6"), "unicast": n.get("info_unicast"),
            "id": n.get("id")}


def shodan_internetdb(ip: str) -> dict:
    return http_json(f"https://internetdb.shodan.io/{ip}")


# --------------------------------------------------------------------------- #
# Synthèse / interprétation
# --------------------------------------------------------------------------- #
def ok(d) -> bool:
    return isinstance(d, dict) and "_error" not in d


def pick(*vals):
    for v in vals:
        if v not in (None, "", [], {}):
            return v
    return None


def analyse(r: dict) -> dict:
    """Déduit nature de l'adresse, opérateur, précision de la géolocalisation."""
    ip = r["ip"]
    lg = r["geo_local"] if ok(r["geo_local"]) else {}
    og = r["geo_online"] if ok(r["geo_online"]) else {}
    rd = r["rdap"] if ok(r["rdap"]) else {}
    pdb = r["peeringdb"] if ok(r["peeringdb"]) else {}
    sh = r["shodan"] if ok(r["shodan"]) else {}
    hostnames = list(dict.fromkeys(h for h in [r["rdns"].get("hostname")] + sh.get("hostnames", []) if h))

    asn = pick(lg.get("asn"), og.get("asn"))
    as_org = pick(lg.get("as_org"), og.get("as_org"), og.get("isp"))
    blob = " ".join([str(as_org or ""), str(pdb.get("name") or ""), str(rd.get("name") or "")]
                    + hostnames).lower()

    cdn = None
    for kw, name in CDN_KEYWORDS.items():
        if kw in blob.replace("-", "").replace(" ", "") or kw in blob:
            cdn = name
            break
    if not cdn and asn in ANYCAST_ASN:
        cdn = ANYCAST_ASN[asn]
    anycast = bool(cdn) or "anycast" in " ".join(rd.get("remarks", [])).lower()

    ptype = (pdb.get("type") or "").lower()
    if cdn:
        nature = f"Serveur cloud / CDN ({cdn})"
    elif any(k in blob for k in CLOUD_KEYWORDS) or ptype in ("content", "enterprise"):
        nature = "Hébergeur / serveur cloud"
    elif "cable" in ptype or "dsl" in ptype or "isp" in ptype or ptype == "nsp":
        nature = "Fournisseur d'accès (probablement abonné / résidentiel)"
    elif ipaddress.ip_address(ip).is_private:
        nature = "Adresse privée (réseau local, non routable sur Internet)"
    else:
        nature = "Indéterminée"

    city = pick(lg.get("city"), og.get("city"))
    region = pick(lg.get("region"), og.get("region"))
    country = pick(lg.get("country"), og.get("country"))
    location = ", ".join(x for x in (city, region, country) if x) or None

    if anycast:
        precision = ("Adresse anycast (CDN / accélérateur) : elle est annoncée depuis "
                     "de nombreux sites dans le monde, la ville indiquée n'est qu'un point "
                     "d'entrée, le serveur réel se trouve ailleurs.")
    elif "Hébergeur" in nature:
        precision = ("Ville du centre de données ou du point de présence de l'hébergeur ; "
                     "fiable à l'échelle du pays, approximative à l'échelle de la ville.")
    else:
        precision = ("Ville de l'équipement réseau de l'opérateur, pas l'adresse de "
                     "l'utilisateur (précision typique : 10 à 50 km).")

    ents = rd.get("entities", [])

    def role(name):
        return [e for e in ents if name in (e.get("roles") or [])]

    abuse = role("abuse")
    abuse_mail = next((m for e in abuse for m in e.get("emails", [])), None)
    holder = role("registrant") or role("administrative")
    holder_name = holder[0].get("name") if holder else rd.get("name")

    web = {p: v for p, v in r["http"].items() if ok(v)}
    first = next(iter(web.values()), {})
    techs = []
    for v in web.values():
        for t in v.get("technologies", []):
            if t not in techs:
                techs.append(t)

    return {
        "asn": asn, "as_org": as_org, "cdn": cdn, "anycast": anycast, "nature": nature,
        "location": location, "precision": precision,
        "coords": (pick(lg.get("lat"), og.get("lat")), pick(lg.get("lon"), og.get("lon"))),
        "network": pick(", ".join(rd.get("cidr", [])), lg.get("network")),
        "holder": holder_name, "abuse": abuse_mail, "hostnames": hostnames,
        "site_name": pick(first.get("title"), first.get("h1")),
        "site_port": next(iter(web.keys()), None),
        "technologies": techs, "server": first.get("server"),
    }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def investigate(ip: str, ports: list[int], out_dir: str, do_shot: bool = True,
                offline: bool = False) -> dict:
    started = now_utc()
    stamp = started.strftime("%Y%m%d-%H%M%S")
    cap_dir = os.path.join(out_dir, "captures")
    os.makedirs(cap_dir, exist_ok=True)

    r: dict = {"ip": ip, "generated": started.strftime("%Y-%m-%d %H:%M UTC"),
               "stamp": stamp, "ports": ports, "app": f"{APP} {VERSION}",
               "mode": "actif" if ports else "passif"}

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        log(f"Scan des ports {', '.join(map(str, ports))} …")
        f_scan = {p: ex.submit(scan_port, ip, p) for p in ports}
        f_rdns = ex.submit(safe, reverse_dns, ip)
        f_lgeo = ex.submit(safe, local_geo, ip)
        if offline:
            off = {"_error": "mode hors-ligne"}
            f_ogeo = f_rdap = f_sh = None
        else:
            log("Interrogation RDAP, géolocalisation, Shodan InternetDB …")
            f_ogeo = ex.submit(safe, online_geo, ip)
            f_rdap = ex.submit(safe, rdap, ip)
            f_sh = ex.submit(safe, shodan_internetdb, ip)
        r["scan"] = {p: f.result() for p, f in f_scan.items()}
        r["rdns"] = f_rdns.result() if ok(f_rdns.result()) else {"hostname": None}
        r["geo_local"] = f_lgeo.result()
        r["geo_online"] = f_ogeo.result() if f_ogeo else off
        r["rdap"] = f_rdap.result() if f_rdap else off
        r["shodan"] = f_sh.result() if f_sh else off

        open_ports = [p for p, s in r["scan"].items() if s["state"] == "ouvert"]
        for p in ports:
            log(f"Port {p} : {r['scan'][p]['state']}")
        log("Analyse HTTP/HTTPS …" if open_ports else "Aucun port web ouvert.")
        f_http = {p: ex.submit(safe, http_probe, ip, p) for p in open_ports}
        asn = pick((r["geo_local"] or {}).get("asn"), (r["geo_online"] or {}).get("asn"))
        f_pdb = ex.submit(safe, peeringdb, int(asn)) if (asn and not offline) else None
        r["http"] = {p: f.result() for p, f in f_http.items()}
        r["peeringdb"] = f_pdb.result() if f_pdb else {"_error": "ASN inconnu" if not offline else "mode hors-ligne"}

    r["screenshots"] = {}
    if do_shot:
        for p, h in r["http"].items():
            if not ok(h):
                continue
            log(f"Capture d'écran du port {p} …")
            path = os.path.join(cap_dir, f"{ip}-{p}-{stamp}.png")
            res = safe(screenshot, h["url"], path)
            if ok(res) and os.path.exists(path):
                with open(path, "rb") as fh:
                    res["b64"] = base64.b64encode(fh.read()).decode()
            r["screenshots"][p] = res

    r["summary"] = analyse(r)
    r["duration_s"] = round((now_utc() - started).total_seconds(), 1)
    return r


# --------------------------------------------------------------------------- #
# Rendu HTML
# --------------------------------------------------------------------------- #
E = lambda v: html.escape(str(v)) if v not in (None, "") else '<span class="na">—</span>'  # noqa: E731


def rows(items) -> str:
    """items : liste de (champ, valeur_html, source)."""
    out = []
    for it in items:
        k, v = it[0], it[1]
        src = it[2] if len(it) > 2 else None
        if v in (None, "", []):
            v = '<span class="na">—</span>'
        out.append(f"<tr><th>{html.escape(k)}</th><td>{v}</td>"
                   + (f'<td class="src">{html.escape(src)}</td>' if src is not None else "")
                   + "</tr>")
    return "\n".join(out)


def table(items, src_col=False, head=None) -> str:
    h = ""
    if head:
        h = "<thead><tr>" + "".join(f"<th>{html.escape(x)}</th>" for x in head) + "</tr></thead>"
    return f'<table class="kv{" src3" if src_col else ""}">{h}<tbody>{rows(items)}</tbody></table>'


def lst(values) -> str:
    values = [v for v in (values or []) if v not in (None, "")]
    return ", ".join(html.escape(str(v)) for v in values) if values else ""


def err(d) -> str:
    return f'<p class="err">Données indisponibles : {html.escape(d.get("_error", "?"))}</p>'


def badge(text, kind="") -> str:
    return f'<span class="badge {kind}">{html.escape(text)}</span>'


def render_html(r: dict) -> str:
    s = r["summary"]
    ip = r["ip"]
    lg, og, rd = r["geo_local"], r["geo_online"], r["rdap"]
    pdb, sh = r["peeringdb"], r["shodan"]

    # ---------- Fiche d'identité ----------
    apps = []
    for p, h in r["http"].items():
        if ok(h):
            apps.append(f"{p}/{'HTTPS' if p in (443, 8443) else 'HTTP'} — "
                        + lst([h.get("server")] + h.get("technologies", [])))
    for p, sc in r["scan"].items():
        if sc["state"] != "ouvert":
            apps.append(f"{p} : {sc['state']}")
    geo_src = []
    if ok(lg) and lg.get("city_db"):
        geo_src.append(f"base locale {lg['city_db']}")
    if ok(og):
        geo_src.append(og.get("source"))
    loc = html.escape(s["location"]) if s["location"] else ""
    if s["anycast"]:
        loc += " — " + badge("anycast, lieu non significatif", "warn")
    op = lst([f"AS{s['asn']}" if s["asn"] else None, s["as_org"]])
    if ok(pdb) and pdb.get("type"):
        op += f" — {html.escape(pdb['type'])}"
    if s["cdn"]:
        op += f" — {html.escape(s['cdn'])}"
    shot_cell = ""
    for p, sc in r["screenshots"].items():
        if ok(sc):
            shot_cell += f'<a href="#shot-{p}">voir la capture du port {p}</a><br>'
    ident = [
        ("Cible", E(ip), "saisie"),
        ("Nom du site", E(s["site_name"]),
         f"page web lue sur le port {s['site_port']}" if s["site_port"] else "aucune page web"),
        ("Application", "<br>".join(html.escape(a) for a in apps),
         "lecture directe des ports indiqués (mode actif)"),
        ("Localisation IP", loc, "; ".join(geo_src) or "indisponible"),
        ("Nature", E(s["nature"]), "déduction (ASN, PeeringDB, DNS)"),
        ("Réseau", lst([s["network"], rd.get("name") if ok(rd) else None]),
         f"registre Internet, RDAP {rd.get('server', '')}" if ok(rd) else "base locale"),
        ("Opérateur", op, "base locale dbip-asn-lite.mmdb ; PeeringDB"),
        ("Noms d'hôte", "<br>".join(html.escape(h) for h in s["hostnames"]),
         "DNS inverse ; Shodan InternetDB"),
        ("Contact abus", E(s["abuse"]), "RDAP"),
        ("Capture", shot_cell, "navigateur sans interface, Chromium"),
    ]

    # ---------- Adresse ----------
    addr = [
        ("Localisation estimée", E(s["location"])),
        ("Coordonnées", E(f"{s['coords'][0]}, {s['coords'][1]}") if s["coords"][0] is not None else ""),
        ("Précision", E(s["precision"])),
        ("Nature de l'adresse", E(s["nature"])),
        ("Titulaire du bloc", E(s["holder"])),
        ("FAI / opérateur", op),
        ("DNS inverse", E(r["rdns"].get("hostname"))),
        ("Contact abus", E(s["abuse"])),
        ("Fuseau horaire", E(og.get("timezone")) if ok(og) else ""),
    ]
    if s["coords"][0] is not None:
        la, lo = s["coords"]
        addr.append(("Carte", f'<a href="https://www.openstreetmap.org/?mlat={la}&mlon={lo}#map=10/{la}/{lo}" '
                              f'target="_blank" rel="noopener">ouvrir dans OpenStreetMap</a>'))

    # ---------- Bases locales / sources de géoloc ----------
    geo_rows = []
    for d, name in ((lg, "local"), (og, "online")):
        if not ok(d):
            geo_rows.append(f'<tr><td>{"bases DB-IP locales" if name == "local" else "service en ligne"}</td>'
                            f'<td colspan="4" class="na">{html.escape(d.get("_error", ""))}</td></tr>')
            continue
        src = lst([d.get("city_db"), d.get("asn_db")]) if name == "local" else html.escape(d.get("source", ""))
        lieu = lst([d.get("city"), d.get("region"), d.get("country")])
        coord = f"{d.get('lat')}, {d.get('lon')}" if d.get("lat") is not None else ""
        oper = lst([f"AS{d['asn']}" if d.get("asn") else None, d.get("as_org")])
        geo_rows.append(f"<tr><td>{src}</td><td>{lieu}</td><td>{html.escape(coord)}</td>"
                        f"<td>{E(d.get('network'))}</td><td>{oper}</td></tr>")
    geo_tbl = ('<table class="grid"><thead><tr><th>Source</th><th>Lieu</th><th>Coordonnées</th>'
               '<th>Réseau</th><th>Opérateur</th></tr></thead><tbody>' + "".join(geo_rows)
               + "</tbody></table>")

    # ---------- RDAP ----------
    if ok(rd):
        rd_items = [
            ("Nom du bloc", E(rd.get("name"))), ("Handle", E(rd.get("handle"))),
            ("Plage", E(f"{rd.get('start')} – {rd.get('end')}")),
            ("CIDR", "<br>".join(html.escape(c) for c in rd.get("cidr", []))),
            ("Type", E(rd.get("type"))), ("Pays", E(rd.get("country"))),
            ("Bloc parent", E(rd.get("parent"))),
            ("Dernière modification", E(rd.get("last_changed"))),
            ("Enregistrement", E(rd.get("registration"))),
        ]
        for rem in rd.get("remarks", []):
            rd_items.append(("Remarque", E(rem)))
        for e in rd.get("entities", []):
            roles = ", ".join(e.get("roles") or []) or "entité"
            val = "<br>".join(x for x in [
                f"<b>{html.escape(e['name'])}</b>" if e.get("name") else "",
                html.escape(e["address"]) if e.get("address") else "",
                lst(e.get("emails")), lst(e.get("phones")),
                f'<span class="na">{html.escape(e["handle"])}</span>' if e.get("handle") else ""] if x)
            rd_items.append((roles, val))
        rdap_html = table(rd_items)
    else:
        rdap_html = err(rd)

    # ---------- PeeringDB ----------
    if ok(pdb):
        site = pdb.get("website")
        pdb_html = table([
            ("Nom", E(pdb.get("name"))), ("Aussi connu comme", E(pdb.get("aka"))),
            ("Type de réseau", E(pdb.get("type"))), ("Portée", E(pdb.get("scope"))),
            ("Trafic", E(pdb.get("traffic"))), ("Politique de peering", E(pdb.get("policy"))),
            ("AS-SET IRR", E(pdb.get("irr_as_set"))),
            ("Préfixes annoncés", E(f"{pdb.get('prefixes4')} IPv4 / {pdb.get('prefixes6')} IPv6")),
            ("Site", f'<a href="{html.escape(site)}" target="_blank" rel="noopener">{html.escape(site)}</a>' if site else ""),
            ("Fiche", f'<a href="https://www.peeringdb.com/net/{pdb.get("id")}" target="_blank" rel="noopener">peeringdb.com/net/{pdb.get("id")}</a>'),
        ])
    else:
        pdb_html = err(pdb)

    # ---------- Shodan ----------
    if ok(sh):
        vulns = sh.get("vulns", [])
        vl = ", ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(v)}" target="_blank" '
                       f'rel="noopener">{html.escape(v)}</a>' for v in vulns)
        sh_html = table([
            ("Ports ouverts", lst(sh.get("ports"))),
            ("Noms d'hôte", "<br>".join(html.escape(h) for h in sh.get("hostnames", []))),
            ("Logiciels (CPE)", "<br>".join(html.escape(c) for c in sh.get("cpes", []))),
            ("Étiquettes", lst(sh.get("tags"))),
            ("Vulnérabilités connues", vl + (" " + badge(f"{len(vulns)} CVE", "bad") if vulns else "")),
        ])
    else:
        sh_html = err(sh)

    # ---------- Ports web ----------
    port_sections = []
    for p in r["ports"]:
        sc = r["scan"][p]
        h = r["http"].get(p)
        title = f"Port {p} — {'HTTPS' if p in (443, 8443) else 'HTTP'}"
        state_kind = "ok" if sc["state"] == "ouvert" else "bad"
        body = f'<p>État : {badge(sc["state"], state_kind)}'
        if sc.get("latency_ms") is not None:
            body += f' &nbsp; latence TCP : {sc["latency_ms"]} ms'
        body += "</p>"
        if h is not None and not ok(h):
            body += err(h)
        elif h:
            sec_p = "<br>".join(html.escape(x) for x in h["security_present"])
            sec_m = "<br>".join(f'<span class="miss">{html.escape(x)}</span>' for x in h["security_missing"])
            cookies = "<br>".join(f"{html.escape(c['name'])}"
                                  + (f' <span class="na">({html.escape(" ; ".join(c["flags"]))})</span>' if c["flags"] else
                                     ' <span class="miss">(sans Secure / HttpOnly)</span>')
                                  for c in h["cookies"])
            items = [
                ("URL", E(h["url"])),
                ("Réponse", E(f"{h['status']} {h['reason']}")),
                ("Redirections", "<br>".join(html.escape(x) for x in h["redirects"])),
                ("URL finale", E(h["final_url"])),
                ("Titre de la page", E(h.get("title"))),
                ("Titre principal (h1)", E(h.get("h1"))),
                ("Description", E(h.get("description"))),
                ("Serveur", E(h.get("server"))),
                ("X-Powered-By", E(h.get("powered_by"))),
                ("Type de contenu", E(h.get("content_type"))),
                ("Taille", E(f"{h['size']:,} octets".replace(",", " "))),
                ("Technologies détectées", "<br>".join(html.escape(t) for t in h["technologies"])),
                ("Cookies", cookies),
                ("Formulaires", E(f"{h['forms']}" + (" (dont un champ mot de passe → page de connexion)" if h["password_field"] else ""))),
                ("Liens", E(h.get("links"))),
                ("Adresses e-mail visibles", lst(h.get("emails"))),
                ("En-têtes de sécurité présents", sec_p),
                ("En-têtes de sécurité absents", sec_m),
            ]
            tls = h.get("tls")
            if tls is not None:
                if ok(tls):
                    flags = []
                    if tls.get("expired"):
                        flags.append(badge("expiré", "bad"))
                    if tls.get("self_signed"):
                        flags.append(badge("auto-signé", "warn"))
                    items += [
                        ("TLS", E(f"{tls.get('protocol')} — {tls.get('cipher')}")),
                        ("Certificat — sujet", E(tls.get("subject")) + " " + " ".join(flags)),
                        ("Certificat — émetteur", E(tls.get("issuer"))),
                        ("Validité", E(f"{tls.get('not_before')} → {tls.get('not_after')}") if tls.get("not_before") else ""),
                        ("Noms (SAN)", "<br>".join(html.escape(x) for x in tls.get("san", [])[:30])),
                        ("Empreinte SHA-256", f'<code class="small">{html.escape(tls["sha256"])}</code>'),
                    ]
                else:
                    items.append(("TLS", err(tls)))
            body += table(items)
            hdrs = "\n".join(f"{k}: {v}" for k, v in h["headers"].items())
            body += f"<details><summary>En-têtes HTTP bruts</summary><pre>{html.escape(hdrs)}</pre></details>"
            body += "<h4>robots.txt :</h4>" + (f"<pre>{html.escape(h['robots'])}</pre>" if h.get("robots") else '<p class="na">absent</p>')
            if h.get("security_txt"):
                body += f"<h4>security.txt :</h4><pre>{html.escape(h['security_txt'])}</pre>"
            if h.get("scripts"):
                body += ("<details><summary>Scripts chargés</summary><pre>"
                         + html.escape("\n".join(h["scripts"])) + "</pre></details>")
            shot = r["screenshots"].get(p)
            if shot is not None:
                if ok(shot) and shot.get("b64"):
                    body += (f'<h4 id="shot-{p}">Capture d\'écran</h4>'
                             f'<p class="na small">{html.escape(shot["path"])}</p>'
                             f'<a href="data:image/png;base64,{shot["b64"]}" target="_blank">'
                             f'<img class="shot" alt="capture port {p}" src="data:image/png;base64,{shot["b64"]}"></a>')
                else:
                    body += f'<h4 id="shot-{p}">Capture d\'écran</h4>' + err(shot)
        port_sections.append(f'<section class="card"><h2>{html.escape(title)}</h2>{body}</section>')

    raw = dict(r)
    raw["screenshots"] = {p: {k: v for k, v in sc.items() if k != "b64"} for p, sc in r["screenshots"].items()}
    raw_json = html.escape(json.dumps(raw, indent=2, ensure_ascii=False, default=str))

    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(ip)} — {APP}</title>
<style>
:root{{--bg:#f4f5f8;--card:#fff;--fg:#1d2330;--muted:#6b7280;--line:#e3e6ec;--head:#f0f2f6;
--accent:#2457d6;--ok:#127a3e;--okbg:#e3f5ea;--bad:#b42318;--badbg:#fde8e7;--warn:#9a6700;--warnbg:#fff4d6}}
@media (prefers-color-scheme:dark){{:root{{--bg:#11141a;--card:#1a1e26;--fg:#e6e9ef;--muted:#9aa3b2;
--line:#2c323d;--head:#222733;--accent:#7aa2ff;--ok:#5fd394;--okbg:#14301f;--bad:#ff8a80;--badbg:#3a1714;
--warn:#f5c451;--warnbg:#3a2e10}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
.wrap{{max-width:980px;margin:0 auto;padding:24px 16px 48px}}
header h1{{margin:0;font-size:30px;letter-spacing:-.5px}}
header p{{margin:4px 0 0;color:var(--muted)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-top:18px}}
.card h2{{margin:0 0 12px;font-size:19px}}
h4{{margin:18px 0 6px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}
table.kv th{{width:30%;font-weight:600}}
table.src3 td.src{{width:26%;color:var(--muted);font-size:13px}}
thead th{{background:var(--head);font-size:13px}}
table.grid td{{font-size:13px}}
.na{{color:var(--muted)}} .small{{font-size:12px}}
.err{{color:var(--bad);background:var(--badbg);padding:8px 12px;border-radius:8px;font-size:14px}}
.miss{{color:var(--bad)}}
.badge{{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;background:var(--head)}}
.badge.ok{{color:var(--ok);background:var(--okbg)}} .badge.bad{{color:var(--bad);background:var(--badbg)}}
.badge.warn{{color:var(--warn);background:var(--warnbg)}}
pre{{background:var(--head);padding:10px 12px;border-radius:8px;overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-all}}
img.shot{{max-width:100%;border:1px solid var(--line);border-radius:8px;display:block}}
a{{color:var(--accent)}}
details summary{{cursor:pointer;color:var(--accent);margin-top:10px}}
.note{{color:var(--muted);font-size:13px;margin-top:22px}}
@media (max-width:600px){{table.kv th{{width:38%}} table.src3 td.src{{display:none}} .card{{padding:14px}}}}
@media print{{details{{display:none}} .card{{break-inside:avoid}}}}
</style></head><body><div class="wrap">
<header><h1>{html.escape(ip)}</h1>
<p>Fiche générée le {html.escape(r['generated'])} — mode {html.escape(r['mode'])} — {html.escape(r['app'])} — {r['duration_s']} s</p></header>

<section class="card"><h2>Fiche d'identité</h2>
{table(ident, src_col=True, head=["Champ", "Valeur", "Source"])}</section>

<section class="card"><h2>Adresse {html.escape(ip)}</h2>{table(addr)}
<h4>Bases locales et sources de géolocalisation</h4>{geo_tbl}</section>

<section class="card"><h2>Registre Internet (RDAP)</h2>{rdap_html}</section>

<section class="card"><h2>Opérateur (PeeringDB)</h2>{pdb_html}</section>

<section class="card"><h2>Exposition déjà relevée (Shodan InternetDB)</h2>{sh_html}</section>

{''.join(port_sections)}

<section class="card"><h2>Données brutes</h2>
<details><summary>Afficher le JSON complet</summary><pre>{raw_json}</pre></details></section>

<p class="note">La géolocalisation IP indique la zone où l'opérateur route l'adresse (souvent la ville
d'un équipement réseau), pas l'adresse postale de l'utilisateur. Seul le FAI peut relier une IP à un
abonné, sur réquisition judiciaire. Un VPN, un proxy ou un CGNAT masque l'utilisateur réel.
Inclut des données DB-IP (db-ip.com, licence CC BY 4.0).</p>
</div></body></html>"""


# --------------------------------------------------------------------------- #
# Bases DB-IP
# --------------------------------------------------------------------------- #
def update_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    month = now_utc().strftime("%Y-%m")
    prev = (now_utc().replace(day=1) - dt.timedelta(days=1)).strftime("%Y-%m")
    for kind in ("city", "asn"):
        for m in (month, prev):
            url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{m}.mmdb.gz"
            print(f"Téléchargement {url}")
            try:
                rr = requests.get(url, timeout=120, stream=True)
                if rr.status_code != 200:
                    print(f"  → HTTP {rr.status_code}")
                    continue
                dest = os.path.join(DATA_DIR, f"dbip-{kind}-lite-{m}.mmdb")
                with gzip.GzipFile(fileobj=rr.raw) as gz, open(dest, "wb") as fh:
                    shutil.copyfileobj(gz, fh)
                for old in glob.glob(os.path.join(DATA_DIR, f"dbip-{kind}-lite-*.mmdb")):
                    if old != dest:
                        os.remove(old)
                print(f"  → {dest}")
                break
            except requests.RequestException as exc:
                print(f"  → échec : {exc}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def resolve_target(target: str) -> str:
    target = target.strip()
    target = re.sub(r"^\w+://", "", target).split("/")[0]
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        ip = socket.gethostbyname(target)  # accepte aussi un nom de domaine
        print(f"  {target} → {ip}")
        return ip


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=f"{APP} — rapport HTML complet sur une adresse IP")
    ap.add_argument("ip", nargs="?", help="adresse IP (ou nom de domaine) à analyser")
    ap.add_argument("-p", "--ports", default="80,443", help="ports à analyser (défaut : 80,443)")
    ap.add_argument("-o", "--out", default=os.path.join(BASE_DIR, "rapports"), help="dossier de sortie")
    ap.add_argument("--no-screenshot", action="store_true", help="ne pas faire de capture d'écran")
    ap.add_argument("--offline", action="store_true", help="pas de requête vers les API en ligne")
    ap.add_argument("--no-open", action="store_true", help="ne pas ouvrir le rapport à la fin")
    ap.add_argument("--update-db", action="store_true", help="télécharger les bases DB-IP lite")
    a = ap.parse_args(argv)

    if a.update_db:
        update_db()
        if not a.ip:
            return 0

    print(f"\n=== {APP} {VERSION} ===")
    target = a.ip or input("Adresse IP à analyser : ")
    try:
        ip = resolve_target(target)
    except (OSError, ValueError):
        print(f"Adresse invalide : {target!r}")
        return 2
    ports = [int(x) for x in re.split(r"[,\s]+", a.ports) if x.strip()]
    ipobj = ipaddress.ip_address(ip)
    if ipobj.is_private or ipobj.is_loopback:
        print("  (adresse privée : les sources Internet ne renverront rien d'utile)")

    print(f"\nAnalyse de {ip}\n")
    r = investigate(ip, ports, a.out, do_shot=not a.no_screenshot, offline=a.offline)

    base = os.path.join(a.out, f"{ip}-{r['stamp']}")
    with open(base + ".html", "w", encoding="utf-8") as fh:
        fh.write(render_html(r))
    raw = dict(r)
    raw["screenshots"] = {p: {k: v for k, v in sc.items() if k != "b64"} for p, sc in r["screenshots"].items()}
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2, ensure_ascii=False, default=str)

    s = r["summary"]
    print(f"\n  Site        : {s['site_name'] or '—'}")
    print(f"  Localisation: {s['location'] or '—'}{' (anycast)' if s['anycast'] else ''}")
    print(f"  Opérateur   : {('AS' + str(s['asn']) + ' ') if s['asn'] else ''}{s['as_org'] or '—'}")
    print(f"  Nature      : {s['nature']}")
    print(f"\nRapport HTML : {base}.html")
    print(f"Données JSON : {base}.json\n")
    if not a.no_open:
        webbrowser.open("file://" + os.path.abspath(base + ".html"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
