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

# --------------------------------------------------------------------------- #
# Auto-installation des dépendances dans le Python qui exécute ce script
# (évite les soucis quand plusieurs Python sont installés sous Windows)
# --------------------------------------------------------------------------- #
# Tous les modules externes sont FACULTATIFS : le programme fonctionne avec la seule
# bibliothèque standard de Python. Ils ajoutent du confort s'ils sont installables.
OPTIONAL = {"bs4": ("beautifulsoup4", "analyse HTML plus fine"),
            "maxminddb": ("maxminddb", "bases de géolocalisation locales"),
            "cryptography": ("cryptography", "détail des certificats auto-signés"),
            "playwright": ("playwright", "captures via Playwright ; sinon Edge/Chrome")}
_SKIP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", ".install-skip.json")


def _system_proxy() -> str | None:
    """Proxy configuré dans Windows / variables d'environnement, s'il y en a un."""
    import urllib.request
    px = urllib.request.getproxies()
    return px.get("https") or px.get("http")


def _pypi_reachable() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen("https://pypi.org/simple/pip/", timeout=5).close()
        return True
    except Exception:  # noqa: BLE001
        return False


def _pip_install(pkg: str) -> bool:
    import subprocess
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
           "--only-binary=:all:", "--prefer-binary", "--retries", "1", "--timeout", "10", pkg]
    px = _system_proxy()
    if px:
        cmd += ["--proxy", px]
    for extra in ([], ["--user"]):
        try:
            if subprocess.call(cmd + extra, timeout=300) == 0:
                return True
        except subprocess.TimeoutExpired:
            return False
    return False


def _save_skip(mods: list[str]) -> None:
    try:
        os.makedirs(os.path.dirname(_SKIP_FILE), exist_ok=True)
        with open(_SKIP_FILE, "w", encoding="utf-8") as fh:
            json.dump({sys.executable: mods}, fh)
    except OSError:
        pass


def bootstrap() -> None:
    import importlib
    import importlib.util
    if os.environ.get("IPINV_NO_INSTALL"):
        return
    try:
        with open(_SKIP_FILE, encoding="utf-8") as fh:
            skip = json.load(fh).get(sys.executable, [])
    except (OSError, ValueError):
        skip = []
    todo = [m for m in OPTIONAL if importlib.util.find_spec(m) is None and m not in skip]
    if not todo:
        return
    print("Installation des modules complémentaires (facultatifs) …", flush=True)
    if not _pypi_reachable():
        print("  pypi.org injoignable depuis ce réseau (pare-feu / proxy d'entreprise) :")
        print("  l'application fonctionne quand même, sans ces modules.\n", flush=True)
        _save_skip(skip + todo)
        return
    if importlib.util.find_spec("pip") is None:
        import subprocess
        subprocess.call([sys.executable, "-m", "ensurepip", "--upgrade"])
    failed = []
    for mod in todo:
        pkg, what = OPTIONAL[mod]
        print(f"  → {pkg} ({what}) …", flush=True)
        if not _pip_install(pkg):
            print("    non disponible, ignoré.", flush=True)
            failed.append(mod)
    if failed:
        _save_skip(skip + failed)
    importlib.invalidate_caches()
    import site
    try:
        if site.getusersitepackages() not in sys.path:
            sys.path.append(site.getusersitepackages())
    except Exception:  # noqa: BLE001
        pass
    print(flush=True)


bootstrap()

import http.client  # noqa: E402
import http.cookiejar  # noqa: E402
import urllib.error  # noqa: E402
import urllib.parse  # noqa: E402
import urllib.request  # noqa: E402

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
import threading  # noqa: E402

_log_local = threading.local()


def log(msg: str) -> None:
    """Affiche une étape ; l'interface web peut capter ces messages par thread."""
    sink = getattr(_log_local, "sink", None)
    if sink is not None:
        sink(msg)
    print(f"  [*] {msg}", flush=True)


def set_log_sink(fn) -> None:
    _log_local.sink = fn


def safe(fn, *a, **kw):
    """Exécute fn et capture les erreurs pour ne jamais bloquer le rapport."""
    try:
        return fn(*a, **kw)
    except Exception as exc:  # noqa: BLE001
        return {"_error": f"{type(exc).__name__}: {exc}"}


class HttpError(Exception):
    pass


class Resp:
    def __init__(self, status, reason, url, headers, content, history, jar):
        self.status, self.reason, self.url = status, reason, url
        self.headers, self.content, self.history, self.jar = headers, content, history, jar

    @property
    def text(self) -> str:
        ct = self.headers.get("content-type", "") if isinstance(self.headers, dict) else ""
        m = re.search(r"charset=([\w.-]+)", ct, re.I)
        try:
            return self.content.decode(m.group(1) if m else "utf-8", errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.content.decode("utf-8", errors="replace"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE

# Contexte « ancien » : vieux serveurs n'acceptant que TLS 1.0/1.1 ou des chiffrements faibles
_LEGACY = ssl.create_default_context()
_LEGACY.check_hostname = False
_LEGACY.verify_mode = ssl.CERT_NONE
try:
    _LEGACY.minimum_version = ssl.TLSVersion.TLSv1
    _LEGACY.set_ciphers("DEFAULT:@SECLEVEL=0")
except (ValueError, ssl.SSLError):
    pass


# Connexions « épinglées » : on parle au nom de site (SNI + en-tête Host) tout en se
# connectant à l'IP analysée, comme un navigateur dont le DNS pointerait sur cette IP.
class _PinHTTPConnection(http.client.HTTPConnection):
    pin = None

    def connect(self):
        if self.pin and self.host == self.pin[0]:
            self.sock = socket.create_connection((self.pin[1], self.port), self.timeout)
        else:
            super().connect()


class _PinHTTPSConnection(http.client.HTTPSConnection):
    pin = None

    def connect(self):
        if self.pin and self.host == self.pin[0]:
            sock = socket.create_connection((self.pin[1], self.port), self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        else:
            super().connect()


class _PinHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pin):
        super().__init__()
        self.pin = pin

    def http_open(self, req):
        def make(host, **kw):
            c = _PinHTTPConnection(host, **kw)
            c.pin = self.pin
            return c
        return self.do_open(make, req)


class _PinHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pin, context):
        super().__init__(context=context)
        self.pin = pin
        self.ctx = context

    def https_open(self, req):
        def make(host, **kw):
            c = _PinHTTPSConnection(host, **kw)
            c.pin = self.pin
            return c
        return self.do_open(make, req, context=self.ctx)


def fetch(url: str, timeout: float = TIMEOUT, verify: bool = True, direct: bool = False,
          headers: dict | None = None, jar=None, max_bytes: int = 5_000_000,
          max_redirects: int = 10, pin: tuple | None = None, context=None) -> Resp:
    """GET avec suivi des redirections et cookies (bibliothèque standard uniquement).
    direct=True : connexion directe à la cible, sans le proxy du système."""
    jar = jar if jar is not None else http.cookiejar.CookieJar()
    hdrs = {"User-Agent": UA, "Accept-Language": "fr,en;q=0.8", "Accept": "*/*"}
    hdrs.update(headers or {})
    ctx = context or (None if verify else _INSECURE)
    handlers = [_NoRedirect(), urllib.request.HTTPCookieProcessor(jar)]
    if pin:
        handlers += [_PinHTTPHandler(pin), _PinHTTPSHandler(pin, ctx)]
    else:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if direct:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    history = []
    for _ in range(max_redirects + 1):
        req = urllib.request.Request(url, headers=hdrs)
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            resp = e
        status = resp.status if hasattr(resp, "status") else resp.code
        reason = getattr(resp, "reason", "") or ""
        rh = {k: v for k, v in resp.headers.items()}
        body = resp.read(max_bytes) or b""
        resp.close()
        loc = resp.headers.get("Location")
        if status in (301, 302, 303, 307, 308) and loc:
            nxt = urllib.parse.urljoin(url, loc)
            history.append(f"{status} → {nxt}")
            url = nxt
            continue
        return Resp(status, reason, url, rh, body, history, jar)
    raise HttpError("trop de redirections")


def http_json(url: str, timeout: int = TIMEOUT):
    r = fetch(url, timeout=timeout, headers={"User-Agent": f"{APP}/{VERSION}",
                                             "Accept": "application/json"})
    if r.status == 404:
        return {"_error": "aucune donnée (404)"}
    if r.status >= 400:
        raise HttpError(f"HTTP {r.status} {r.reason}")
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
    der = None
    for ctx in (_INSECURE, _LEGACY):
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni or None) as s:
                    der = s.getpeercert(binary_form=True)
                    info["protocol"] = s.version()
                    c = s.cipher()
                    info["cipher"] = c[0] if c else None
            break
        except (ssl.SSLError, OSError):
            if ctx is _LEGACY:
                raise
    if sni:
        info["sni"] = sni
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
        # Sans 'cryptography' : le module ssl ne décode que les certificats valides
        try:
            vctx = ssl.create_default_context()
            vctx.check_hostname = False
            with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
                with vctx.wrap_socket(sock, server_hostname=sni or None) as s:
                    c = s.getpeercert()
            fmt = lambda t: " ".join(f"{k}={v}" for rdn in t for k, v in rdn)  # noqa: E731
            info["subject"] = fmt(c.get("subject", ()))
            info["issuer"] = fmt(c.get("issuer", ()))
            nb = dt.datetime.utcfromtimestamp(ssl.cert_time_to_seconds(c["notBefore"]))
            na = dt.datetime.utcfromtimestamp(ssl.cert_time_to_seconds(c["notAfter"]))
            info["not_before"], info["not_after"] = nb.strftime("%Y-%m-%d"), na.strftime("%Y-%m-%d")
            info["expired"] = na < dt.datetime.utcnow()
            info["self_signed"] = False
            info["san"] = [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
        except ssl.SSLCertVerificationError as exc:
            info["note"] = f"certificat non reconnu ({exc.verify_message})"
            info["self_signed"] = "self" in str(exc.verify_message).lower()
        except Exception:  # noqa: BLE001
            info["note"] = "détail du certificat indisponible"
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


def _probe_attempts(ip: str, names: list[str], prefer_name: bool, tls: bool):
    """Ordre des essais : (nom ou None, contexte TLS)."""
    first = [names[0]] if (prefer_name and names) else []
    order = first + [None] + [n for n in names if n not in first]
    att = [(n, _INSECURE) for n in order]
    if tls:
        att += [(None, _LEGACY)] + ([(names[0], _LEGACY)] if names else [])
    return att


def http_probe(ip: str, port: int, via_proxy: bool = False, names: list[str] | None = None,
               prefer_name: bool = False) -> dict:
    scheme = "https" if port in (443, 8443) else "http"
    names = [n for n in (names or []) if n][:5]
    res: dict = {}
    errors = []
    r = jar = None
    for name, ctx in _probe_attempts(ip, names, prefer_name, scheme == "https"):
        host = name or ip
        netloc = host if port in (80, 443) else f"{host}:{port}"
        url = f"{scheme}://{netloc}/"
        jar = http.cookiejar.CookieJar()
        try:
            r = fetch(url, verify=False, direct=not via_proxy, jar=jar, context=ctx,
                      pin=(name, ip) if (name and not via_proxy) else None)
        except Exception as exc:  # noqa: BLE001
            label = f"nom {name}" if name else "IP seule"
            if ctx is _LEGACY:
                label += ", TLS ancien"
            errors.append(f"{label} : {getattr(exc, 'reason', exc)}")
            continue
        res["url"] = url
        res["sni"] = name
        res["legacy_tls"] = ctx is _LEGACY
        ok_ctx, ok_pin = ctx, ((name, ip) if (name and not via_proxy) else None)
        break
    if r is None:
        raise HttpError("le serveur refuse la connexion — essais : " + " | ".join(errors))
    res["attempts_failed"] = errors
    if via_proxy:
        res["via_proxy"] = True
    res["status"] = r.status
    res["reason"] = r.reason
    res["final_url"] = r.url
    res["redirects"] = r.history
    res["headers"] = r.headers
    hl = {k.lower(): v for k, v in r.headers.items()}
    res["server"] = hl.get("server")
    res["powered_by"] = hl.get("x-powered-by")
    res["content_type"] = hl.get("content-type")
    res["size"] = len(r.content)
    cookies = []
    for c in jar:
        flags = []
        if c.secure:
            flags.append("Secure")
        if c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"):
            flags.append("HttpOnly")
        ss = c.get_nonstandard_attr("SameSite") or c.get_nonstandard_attr("samesite")
        if ss:
            flags.append(f"SameSite={ss}")
        cookies.append({"name": c.name, "domain": c.domain, "flags": flags})
    # cookies refusées par la politique de domaine (cible = IP) : lecture brute des en-têtes
    for k, v in r.headers.items():
        if k.lower() == "set-cookie":
            name = v.split("=", 1)[0].strip()
            if name and name not in [x["name"] for x in cookies]:
                fl = [f for f in ("Secure", "HttpOnly") if re.search(rf";\s*{f}\b", v, re.I)]
                cookies.append({"name": name, "domain": "", "flags": fl})
    res["cookies"] = cookies
    body = r.text if "html" in (res["content_type"] or "html") else ""
    res.update(parse_html(body))
    res["technologies"] = detect_tech(hl, body, [c["name"] for c in cookies])
    res["security_present"] = [h for h in SECURITY_HEADERS if h in hl]
    res["security_missing"] = [h for h in SECURITY_HEADERS if h not in hl]
    # robots.txt / security.txt
    for path, key in (("/robots.txt", "robots"), ("/.well-known/security.txt", "security_txt")):
        try:
            rr = fetch(res["url"].rstrip("/") + path, verify=False, direct=not via_proxy,
                       jar=jar, max_bytes=20000, context=ok_ctx, pin=ok_pin)
            ok = rr.status == 200 and "<html" not in rr.text[:300].lower()
            res[key] = rr.text[:3000] if ok and rr.text.strip() else None
        except Exception:  # noqa: BLE001
            res[key] = None
    if scheme == "https":
        res["tls"] = safe(tls_info, ip, port, res.get("sni"))
    return res


def install_chromium() -> None:
    import subprocess
    print("  [*] Téléchargement du navigateur Chromium pour les captures (une seule fois) …",
          flush=True)
    subprocess.call([sys.executable, "-m", "playwright", "install", "chromium"])


def find_system_browser() -> str | None:
    """Edge / Chrome / Chromium déjà installé sur la machine."""
    cands = [os.environ.get("IPINV_CHROMIUM")]
    if os.name == "nt":
        for base in (os.environ.get("PROGRAMFILES(X86)"), os.environ.get("PROGRAMFILES"),
                     os.environ.get("LOCALAPPDATA")):
            if base:
                cands += [os.path.join(base, r"Microsoft\Edge\Application\msedge.exe"),
                          os.path.join(base, r"Google\Chrome\Application\chrome.exe")]
    elif sys.platform == "darwin":
        cands += ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                  "/Applications/Chromium.app/Contents/MacOS/Chromium"]
    cands += [shutil.which(n) for n in ("google-chrome", "chromium", "chromium-browser",
                                        "microsoft-edge", "msedge", "chrome")]
    return next((c for c in cands if c and os.path.isfile(c)), None)


def _resolver_args(pin) -> list[str]:
    return [f"--host-resolver-rules=MAP {pin[0]} {pin[1]}"] if pin else []


def screenshot_cli(url: str, path: str, pin=None) -> dict:
    """Capture via le navigateur installé en mode headless (sans Playwright)."""
    import subprocess
    import tempfile
    exe = find_system_browser()
    if not exe:
        return {"_error": "aucun navigateur Edge/Chrome trouvé pour la capture"}
    with tempfile.TemporaryDirectory() as prof:
        cmd = [exe, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
               "--ignore-certificate-errors", f"--user-data-dir={prof}",
               "--window-size=1366,850", "--virtual-time-budget=8000",
               f"--user-agent={UA}", *_resolver_args(pin),
               f"--screenshot={os.path.abspath(path)}", url]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.insert(1, "--no-sandbox")
        if os.path.exists(path):
            os.remove(path)
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import time
        deadline, last = time.time() + 60, -1
        while time.time() < deadline and proc.poll() is None:
            time.sleep(0.5)
            if os.path.exists(path):  # image écrite : on n'attend pas la fermeture
                size = os.path.getsize(path)
                if size and size == last:
                    break
                last = size
        if proc.poll() is None:
            proc.kill()
            proc.wait(10)
    if not os.path.exists(path):
        return {"_error": f"la capture via {os.path.basename(exe)} a échoué"}
    return {"path": path, "via": os.path.basename(exe)}


def screenshot_playwright(url: str, path: str, pin=None) -> dict:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        exe = os.environ.get("IPINV_CHROMIUM")
        attempts = [{"executable_path": exe}] if exe else []
        attempts += [{}, {"channel": "msedge"}, {"channel": "chrome"}]
        for kw in attempts:
            kw["args"] = _resolver_args(pin)
        browser, last = None, None
        for kw in attempts:
            try:
                browser = p.chromium.launch(**kw)
                break
            except Exception as exc:  # noqa: BLE001
                last = exc
        if browser is None:
            install_chromium()
            try:
                browser = p.chromium.launch(args=_resolver_args(pin))
            except Exception:  # noqa: BLE001
                raise last
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
    return {"path": path, "via": "Playwright / Chromium"}


def screenshot(url: str, path: str, pin=None) -> dict:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return screenshot_cli(url, path, pin)
    try:
        return screenshot_playwright(url, path, pin)
    except Exception:  # noqa: BLE001
        return screenshot_cli(url, path, pin)


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
# Contacts : site web, mentions légales, schema.org, security.txt, RDAP domaine
# --------------------------------------------------------------------------- #
CONTACT_KEYWORDS = re.compile(
    r"contact|nous-?joindre|joindre|mentions|legal|l[ée]gales|impressum|imprint|a-?propos|about|"
    r"support|aide|help|assistance|sav|service-?client|customer|status|statut|qui-sommes",
    re.I)
CONTACT_FALLBACK_PATHS = ["/contact", "/contact-us", "/nous-contacter", "/mentions-legales",
                          "/legal", "/impressum", "/support", "/humans.txt"]
SOCIAL = {"linkedin.com": "LinkedIn", "twitter.com": "X / Twitter", "x.com": "X / Twitter",
          "facebook.com": "Facebook", "instagram.com": "Instagram", "youtube.com": "YouTube",
          "github.com": "GitHub", "t.me": "Telegram", "wa.me": "WhatsApp", "tiktok.com": "TikTok"}
_EMAIL_RX = re.compile(r"(?<![\w.+-])[A-Za-z0-9][\w.+-]{0,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b")
_PHONE_RX = re.compile(
    r"(?<![\w+])(?:\+33\s?\(?0?\)?\s?[1-9]|0[1-9])(?:[\s.\-]?\d{2}){4}(?!\d)"   # France
    r"|(?<![\w+])\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?(?:[\s.\-]?\d{2,4}){2,4}(?!\d)")  # international
_BAD_EMAIL_END = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js", ".ico")


def registered_domain(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().strip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) < 2:
        return None
    two = ".".join(parts[-2:])
    if len(parts) >= 3 and (parts[-2] in ("co", "com", "net", "org", "gov", "gouv", "ac", "edu")
                            or two in ("asso.fr", "nom.fr", "presse.fr")):
        return ".".join(parts[-3:])
    return two


def _visible_text(body: str) -> str:
    t = re.sub(r"(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>", " ", body)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = html.unescape(t)
    t = re.sub(r"\s*[\[\(\{]\s*(?:at|arobase)\s*[\]\)\}]\s*|\s+arobase\s+", "@", t, flags=re.I)
    t = re.sub(r"\s*[\[\(\{]\s*(?:dot|point)\s*[\]\)\}]\s*", ".", t, flags=re.I)
    return re.sub(r"\s+", " ", t)


def _clean_email(e: str) -> str | None:
    e = e.strip().strip(".").lower()
    local = e.split("@")[0]
    if e.endswith(_BAD_EMAIL_END) or len(local) > 40 or re.fullmatch(r"[0-9a-f]{16,}", local):
        return None
    if any(x in e for x in ("sentry", "wixpress", "@example.", "domain.com", "email.com", "@2x")):
        return None
    return e


def _clean_phone(p: str) -> str | None:
    digits = re.sub(r"\D", "", p)
    if not 9 <= len(digits) <= 15 or len(set(digits)) <= 2:
        return None
    fr = digits[2:] if digits.startswith("33") and len(digits) == 11 else \
        digits[3:] if digits.startswith("330") and len(digits) == 12 else None
    if fr:  # +33 1 23 45 67 89
        return "+33 " + fr[0] + " " + " ".join(fr[i:i + 2] for i in range(1, 9, 2))
    if digits.startswith("0") and len(digits) == 10 and not p.strip().startswith("+"):
        return " ".join(digits[i:i + 2] for i in range(0, 10, 2))
    return re.sub(r"\s+", " ", p.strip())


def _phone_key(p: str) -> str:
    d = re.sub(r"\D", "", p)
    if d.startswith("33") and len(d) == 11:
        d = "0" + d[2:]
    return d


def _jsonld_contacts(body: str) -> list[dict]:
    found = []

    def walk(o, org=None):
        if isinstance(o, list):
            for x in o:
                walk(x, org)
        elif isinstance(o, dict):
            name = o.get("name") if isinstance(o.get("name"), str) else org
            for key, kind in (("email", "email"), ("telephone", "téléphone"), ("faxNumber", "fax")):
                v = o.get(key)
                for val in (v if isinstance(v, list) else [v]):
                    if isinstance(val, str) and val.strip():
                        found.append({"kind": kind, "value": val.replace("mailto:", "").strip(),
                                      "label": o.get("contactType") or name})
            adr = o.get("address")
            if isinstance(adr, dict):
                txt = ", ".join(str(adr[k]) for k in ("streetAddress", "postalCode", "addressLocality",
                                                       "addressRegion", "addressCountry")
                                if isinstance(adr.get(k), (str, int)))
                if txt:
                    found.append({"kind": "adresse", "value": txt, "label": name})
            elif isinstance(adr, str) and adr.strip():
                found.append({"kind": "adresse", "value": adr.strip(), "label": name})
            for k, v in o.items():
                if k != "address" and isinstance(v, (dict, list)):
                    walk(v, name)

    for m in re.finditer(r'(?is)<script[^>]+application/ld\+json[^>]*>(.*?)</script>', body):
        try:
            walk(json.loads(m.group(1).strip()))
        except ValueError:
            continue
    return found


def _extract_page_contacts(url: str, body: str) -> dict:
    out = {"emails": set(), "phones": set(), "social": {}, "form": False, "jsonld": [],
           "links": [], "title": None}
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    if m:
        out["title"] = " ".join(html.unescape(m.group(1)).split())[:120]
    for href in re.findall(r'(?i)href\s*=\s*["\']mailto:([^"\'?]+)', body):
        e = _clean_email(urllib.parse.unquote(href))
        if e:
            out["emails"].add(e)
    for href in re.findall(r'(?i)href\s*=\s*["\']tel:([^"\']+)', body):
        p = _clean_phone(urllib.parse.unquote(href))
        if p:
            out["phones"].add(p)
    text = _visible_text(body)
    for e in _EMAIL_RX.findall(text):
        e = _clean_email(e)
        if e:
            out["emails"].add(e)
    for ph in _PHONE_RX.findall(text):
        ph = _clean_phone(ph)
        if ph:
            out["phones"].add(ph)
    for href, label in re.findall(r'(?is)<a\b[^>]*href\s*=\s*["\']([^"\'#]+)["\'][^>]*>(.*?)</a>', body):
        absu = urllib.parse.urljoin(url, html.unescape(href.strip()))
        host = urllib.parse.urlparse(absu).netloc.lower()
        for dom, name in SOCIAL.items():
            if host == dom or host.endswith("." + dom):
                out["social"].setdefault(name, absu)
        lab = " ".join(re.sub(r"<[^>]+>", " ", label).split())[:60]
        if absu.startswith("http") and (CONTACT_KEYWORDS.search(urllib.parse.urlparse(absu).path)
                                        or CONTACT_KEYWORDS.search(lab)):
            out["links"].append((absu, lab))
    out["form"] = bool(re.search(r"(?is)<form\b.*?<textarea", body))
    out["jsonld"] = _jsonld_contacts(body)
    return out


def site_contacts(ip: str, h: dict) -> dict:
    """Explore la page d'accueil et les pages contact / mentions légales du site."""
    ctx = _LEGACY if h.get("legacy_tls") else _INSECURE
    direct = not h.get("via_proxy")
    pin = (h["sni"], ip) if h.get("sni") and direct else None
    start = h.get("final_url") or h["url"]
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlparse(start))
    base_dom = registered_domain(urllib.parse.urlparse(start).hostname) or urllib.parse.urlparse(start).hostname

    def get(u):
        r = fetch(u, verify=False, direct=direct, context=ctx, pin=pin, timeout=6, max_bytes=2_000_000)
        ct = r.headers.get("Content-Type", r.headers.get("content-type", ""))
        if r.status != 200 or not ("html" in ct or "text" in ct or not ct):
            return None
        return r.url, r.text

    pages = []
    first = safe(get, start)
    if isinstance(first, tuple):
        pages.append((first[0], _extract_page_contacts(*first)))
    # pages candidates : liens de la page d'accueil, puis chemins usuels
    cand = []
    if pages:
        for u, lab in pages[0][1]["links"]:
            hst = urllib.parse.urlparse(u).hostname or ""
            if (registered_domain(hst) or hst) == base_dom and u.split("#")[0] not in cand:
                cand.append(u.split("#")[0])
    cand = cand[:6]
    if len(cand) < 3:
        cand += [origin + p for p in CONTACT_FALLBACK_PATHS if origin + p not in cand][:5]
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        for u, res in zip(cand, ex.map(lambda u: safe(get, u), cand)):
            if isinstance(res, tuple) and res[0] not in [x[0] for x in pages]:
                pages.append((res[0], _extract_page_contacts(*res)))

    items, seen = [], set()

    def add(kind, value, src, label=None):
        if kind in ("téléphone", "fax"):
            value = _clean_phone(value) or value
            key = ("tel", _phone_key(value))
        else:
            key = (kind, value.lower().rstrip("/"))
        if key in seen:
            return
        seen.add(key)
        items.append({"kind": kind, "value": value, "source": src, "label": label})

    for url, c in pages:
        short = urllib.parse.urlparse(url).path or "/"
        for j in c["jsonld"]:
            add(j["kind"], j["value"], f"données structurées ({short})", j.get("label"))
        for e in sorted(c["emails"]):
            add("email", e, short)
        for ph in sorted(c["phones"]):
            add("téléphone", ph, short)
        if c["form"]:
            add("formulaire", url, short, c["title"])
    social = {}
    for _, c in pages:
        for k, v in c["social"].items():
            social.setdefault(k, v)
    for k, v in social.items():
        add("réseau social", v, "liens du site", k)
    if h.get("security_txt"):
        for line in h["security_txt"].splitlines():
            m = re.match(r"\s*(Contact|Policy|Hiring)\s*:\s*(\S+)", line, re.I)
            if m:
                add("sécurité", m.group(2).replace("mailto:", ""), "/.well-known/security.txt",
                    m.group(1).capitalize())
    return {"origin": origin, "pages": [u for u, _ in pages], "items": items[:60]}


def rdap_domain(domain: str) -> dict:
    d = http_json(f"https://rdap.org/domain/{domain}", timeout=15)
    out = {"domain": d.get("ldhName", domain).lower(), "status": d.get("status", []),
           "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers", [])]}
    for ev in d.get("events", []):
        a = ev.get("eventAction")
        if a in ("registration", "expiration", "last changed"):
            out[a.replace(" ", "_")] = (ev.get("eventDate") or "")[:10]
    ents = _flatten_entities(d.get("entities"))
    out["entities"] = ents
    reg = next((e for e in ents if "registrar" in (e.get("roles") or [])), {})
    out["registrar"] = reg.get("name")
    out["registrar_url"] = next((l.get("href") for e in (d.get("entities") or [])
                                 if "registrar" in (e.get("roles") or [])
                                 for l in (e.get("links") or []) if l.get("href")), None)
    return out


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


def contact_summary(r: dict) -> dict:
    """Meilleur contact par usage : site, sécurité, domaine, hébergeur."""
    items = [it for c in r.get("contacts", {}).values() if ok(c) for it in c["items"]]

    def best(kinds, prefer=r"contact|support|info|hello|bonjour|service|client|accueil|sav|help"):
        cands = [it for it in items if it["kind"] in kinds]
        cands.sort(key=lambda it: (not it["source"].startswith("données structurées"),
                                   not re.search(prefer, it["value"], re.I)))
        return cands[0]["value"] if cands else None

    rd = r.get("rdap_domain") or {}
    reg_abuse = None
    if ok(rd):
        for e in rd.get("entities", []):
            if "abuse" in (e.get("roles") or []) and (e.get("emails") or e.get("phones")):
                reg_abuse = (e.get("emails") or e.get("phones"))[0]
                break
    forms = [it["value"] for it in items if it["kind"] == "formulaire"]
    return {"contact_email": best({"email"}), "contact_phone": best({"téléphone"}),
            "contact_form": forms[0] if forms else None,
            "contact_security": best({"sécurité"}, r"@|mailto"),
            "contact_registrar": reg_abuse,
            "registrar": rd.get("registrar") if ok(rd) else None}


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
                offline: bool = False, hostname: str | None = None) -> dict:
    started = now_utc()
    stamp = started.strftime("%Y%m%d-%H%M%S")
    cap_dir = os.path.join(out_dir, "captures")
    os.makedirs(cap_dir, exist_ok=True)

    r: dict = {"ip": ip, "generated": started.strftime("%Y-%m-%d %H:%M UTC"),
               "stamp": stamp, "ports": ports, "app": f"{APP} {VERSION}",
               "mode": "actif" if ports else "passif", "hostname": hostname}

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
        # Noms de site candidats (SNI / Host) : domaine saisi, noms vus par Shodan, DNS inverse
        sh_names = r["shodan"].get("hostnames", []) if ok(r["shodan"]) else []
        names = list(dict.fromkeys(n for n in [hostname] + sh_names + [r["rdns"].get("hostname")]
                                   if n and "*" not in n))[:5]
        f_http = {p: ex.submit(safe, http_probe, ip, p, False, names, bool(hostname))
                  for p in open_ports}
        # Réseau d'entreprise : connexion directe bloquée mais proxy disponible
        if not offline and _system_proxy():
            for p in ports:
                if p not in open_ports:
                    f_http[p] = ex.submit(safe, http_probe, ip, p, True, names, bool(hostname))
        asn = pick((r["geo_local"] or {}).get("asn"), (r["geo_online"] or {}).get("asn"))
        f_pdb = ex.submit(safe, peeringdb, int(asn)) if (asn and not offline) else None
        r["http"] = {p: f.result() for p, f in f_http.items()}
        for p in list(r["http"]):
            if p in open_ports:
                continue
            if ok(r["http"][p]):  # joignable seulement via le proxy du système
                r["scan"][p]["state"] = "ouvert"
                r["scan"][p]["note"] = "connexion directe bloquée, page lue via le proxy"
                log(f"Port {p} : joignable via le proxy du réseau")
            else:
                del r["http"][p]
        r["peeringdb"] = f_pdb.result() if f_pdb else {"_error": "ASN inconnu" if not offline else "mode hors-ligne"}

    r["screenshots"] = {}
    if do_shot:
        for p, h in r["http"].items():
            if not ok(h):
                continue
            log(f"Capture d'écran du port {p} …")
            path = os.path.join(cap_dir, f"{ip}-{p}-{stamp}.png")
            pin = (h["sni"], ip) if h.get("sni") and not h.get("via_proxy") else None
            res = safe(screenshot, h["url"], path, pin)
            if ok(res) and os.path.exists(path):
                with open(path, "rb") as fh:
                    res["b64"] = base64.b64encode(fh.read()).decode()
            r["screenshots"][p] = res

    # ---------- Contacts ----------
    log("Recherche des contacts (site, mentions légales, security.txt, RDAP domaine) …")
    r["contacts"] = {}
    origins = set()
    for p, h in r["http"].items():
        if not ok(h):
            continue
        origin = urllib.parse.urlparse(h.get("final_url") or h["url"]).netloc
        if origin in origins:
            continue
        origins.add(origin)
        r["contacts"][p] = safe(site_contacts, ip, h)
    dom = hostname or next((h.get("sni") for h in r["http"].values() if ok(h) and h.get("sni")), None)
    if not dom:
        for h in r["http"].values():
            if ok(h):
                dom = urllib.parse.urlparse(h.get("final_url") or "").hostname
                if registered_domain(dom):
                    break
    dom = registered_domain(dom)
    r["domain"] = dom
    if dom and not offline:
        r["rdap_domain"] = safe(rdap_domain, dom)
    else:
        r["rdap_domain"] = {"_error": "aucun nom de domaine identifié" if not dom else "mode hors-ligne"}

    r["summary"] = analyse(r)
    r["summary"].update(contact_summary(r))
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
    values = list(dict.fromkeys(v for v in (values or []) if v not in (None, "")))
    return ", ".join(html.escape(str(v)) for v in values) if values else ""


def err(d) -> str:
    return f'<p class="err">Données indisponibles : {html.escape(d.get("_error", "?"))}</p>'


def badge(text, kind="") -> str:
    return f'<span class="badge {kind}">{html.escape(text)}</span>'


def contact_link(kind: str, value: str) -> str:
    v = html.escape(value)
    if kind in ("email", "sécurité") and "@" in value and not value.startswith("http"):
        return f'<a href="mailto:{v}">{v}</a>'
    if kind in ("téléphone", "fax"):
        tel = re.sub(r"[^\d+]", "", value)
        return f'<a href="tel:{html.escape(tel)}">{v}</a>'
    if value.startswith("http"):
        return f'<a href="{v}" target="_blank" rel="noopener">{v}</a>'
    return v


def render_contacts(r: dict) -> str:
    s = r["summary"]
    guide = [
        ("Panne, question sur le site",
         "<br>".join(x for x in [
             contact_link("email", s["contact_email"]) if s.get("contact_email") else "",
             contact_link("téléphone", s["contact_phone"]) if s.get("contact_phone") else "",
             (f'formulaire : {contact_link("formulaire", s["contact_form"])}' if s.get("contact_form") else "")] if x),
         "contacts publiés par le site"),
        ("Faille de sécurité", contact_link("sécurité", s["contact_security"]) if s.get("contact_security") else "",
         "security.txt"),
        ("Abus, attaque, spam depuis cette IP", contact_link("email", s["abuse"]) if s.get("abuse") else "",
         "hébergeur — RDAP de l'adresse IP"),
        ("Problème lié au nom de domaine",
         lst([s.get("registrar")]) + (("<br>" + contact_link("email", s["contact_registrar"]))
                                      if s.get("contact_registrar") else ""),
         "bureau d'enregistrement — RDAP du domaine"),
    ]
    out = ['<h4>Qui contacter ?</h4>' + table(guide, src_col=True, head=["Besoin", "Contact", "Source"])]
    for p, c in r.get("contacts", {}).items():
        if not ok(c):
            out.append(f"<h4>Site (port {p})</h4>" + err(c))
            continue
        rows_ = "".join(
            f'<tr><td data-l="Type">{html.escape(it["kind"])}</td>'
            f'<td data-l="Coordonnée">{contact_link(it["kind"], it["value"])}</td>'
            f'<td data-l="Libellé">{E(it.get("label"))}</td>'
            f'<td data-l="Trouvé sur">{html.escape(it["source"])}</td></tr>' for it in c["items"])
        body = ('<table class="grid"><thead><tr><th>Type</th><th>Coordonnée</th><th>Libellé</th>'
                f'<th>Trouvé sur</th></tr></thead><tbody>{rows_}</tbody></table>') if rows_ else \
            '<p class="na">Aucune coordonnée publiée trouvée sur les pages explorées.</p>'
        pages = "".join(f"<li>{html.escape(u)}</li>" for u in c["pages"])
        out.append(f'<h4>Coordonnées publiées par le site — {html.escape(c["origin"])}</h4>{body}'
                   f'<details><summary>Pages explorées ({len(c["pages"])})</summary><ul class="small">{pages}</ul></details>')
    rd = r.get("rdap_domain") or {}
    if ok(rd):
        items = [("Domaine", E(rd.get("domain"))), ("Bureau d'enregistrement", E(rd.get("registrar"))),
                 ("Site du registrar", contact_link("url", rd["registrar_url"]) if rd.get("registrar_url") else ""),
                 ("Création", E(rd.get("registration"))), ("Expiration", E(rd.get("expiration"))),
                 ("Dernière modification", E(rd.get("last_changed"))),
                 ("Serveurs DNS", "<br>".join(html.escape(n) for n in rd.get("nameservers", []))),
                 ("Statut", lst(rd.get("status")))]
        for e in rd.get("entities", []):
            val = "<br>".join(x for x in [
                f"<b>{html.escape(e['name'])}</b>" if e.get("name") else "",
                html.escape(e["address"]) if e.get("address") else "",
                "<br>".join(contact_link("email", m) for m in e.get("emails", [])),
                "<br>".join(contact_link("téléphone", t) for t in e.get("phones", []))] if x)
            if val:
                items.append((", ".join(e.get("roles") or []) or "entité", val))
        out.append(f"<h4>Nom de domaine (RDAP)</h4>{table(items)}")
    else:
        out.append(f'<h4>Nom de domaine (RDAP)</h4><p class="na">{html.escape(rd.get("_error", "—"))}</p>')
    return "".join(out)


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
        ("Capture", shot_cell, "navigateur sans interface (Edge, Chrome ou Chromium)"),
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
        geo_rows.append(f'<tr><td data-l="Source">{src}</td><td data-l="Lieu">{lieu}</td>'
                        f'<td data-l="Coordonnées">{html.escape(coord)}</td>'
                        f'<td data-l="Réseau">{E(d.get("network"))}</td><td data-l="Opérateur">{oper}</td></tr>')
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
                ("Nom de site utilisé (SNI / Host)",
                 E(h.get("sni")) + (" " + badge("TLS ancien", "warn") if h.get("legacy_tls") else "")
                 if h.get("sni") or h.get("legacy_tls") else '<span class="na">aucun (IP seule)</span>'),
                ("Essais refusés", "<br>".join(html.escape(x) for x in h.get("attempts_failed", []))),
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
@media (max-width:700px){{
.wrap{{padding:16px 12px 40px}} header h1{{font-size:26px}} .card{{padding:14px;border-radius:10px}}
table.kv thead,table.grid thead{{display:none}}
table.kv,table.kv tbody,table.kv tr,table.kv th,table.kv td,
table.grid,table.grid tbody,table.grid tr,table.grid td{{display:block;width:auto!important}}
table.kv tr,table.grid tr{{padding:10px 2px;border-bottom:1px solid var(--line)}}
table.kv th,table.kv td,table.grid td{{border:0;padding:0;overflow-wrap:break-word;word-break:break-word}}
table.kv th{{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.3px;margin-bottom:2px}}
table.kv td{{font-size:15px}}
table.src3 td.src{{font-size:12px;margin-top:3px}}
table.src3 td.src::before{{content:"Source : "}}
table.grid td{{font-size:14px;padding:1px 0}}
table.grid td[data-l]::before{{content:attr(data-l) " : ";color:var(--muted);font-size:12px}}
}}
@media print{{details{{display:none}} .card{{break-inside:avoid}}}}
</style></head><body><div class="wrap">
<header><h1>{html.escape(ip)}</h1>
<p>Fiche générée le {html.escape(r['generated'])} — mode {html.escape(r['mode'])} — {html.escape(r['app'])} — {r['duration_s']} s</p></header>

<section class="card"><h2>Fiche d'identité</h2>
{table(ident, src_col=True, head=["Champ", "Valeur", "Source"])}</section>

<section class="card"><h2>Contacts</h2>{render_contacts(r)}</section>

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
                req = urllib.request.Request(url, headers={"User-Agent": f"{APP}/{VERSION}"})
                rr = urllib.request.urlopen(req, timeout=30)
                dest = os.path.join(DATA_DIR, f"dbip-{kind}-lite-{m}.mmdb")
                with gzip.GzipFile(fileobj=rr) as gz, open(dest + ".part", "wb") as fh:
                    shutil.copyfileobj(gz, fh)
                os.replace(dest + ".part", dest)
                for old in glob.glob(os.path.join(DATA_DIR, f"dbip-{kind}-lite-*.mmdb")):
                    if old != dest:
                        os.remove(old)
                print(f"  → {dest}")
                break
            except Exception as exc:  # noqa: BLE001
                print(f"  → échec : {exc}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def ensure_db() -> None:
    if maxminddb and not (find_mmdb("city") and find_mmdb("asn")):
        print("Bases de géolocalisation DB-IP absentes : téléchargement (une seule fois) …")
        update_db()


def save_report(r: dict, out_dir: str) -> str:
    """Écrit <ip>-<date>.html et .json ; renvoie le chemin sans extension."""
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"{r['ip']}-{r['stamp']}")
    with open(base + ".html", "w", encoding="utf-8") as fh:
        fh.write(render_html(r))
    raw = dict(r)
    raw["screenshots"] = {p: {k: v for k, v in sc.items() if k != "b64"}
                          for p, sc in r["screenshots"].items()}
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2, ensure_ascii=False, default=str)
    return base


def parse_ports(text: str) -> list[int]:
    ports = []
    for x in re.split(r"[,;\s]+", str(text or "")):
        if x.strip():
            p = int(x)
            if not 1 <= p <= 65535:
                raise ValueError(f"port invalide : {p}")
            if p not in ports:
                ports.append(p)
    return ports or [80, 443]


def resolve(target: str) -> tuple[str, str | None]:
    """Renvoie (ip, nom de domaine saisi ou None)."""
    target = target.strip()
    target = re.sub(r"^\w+://", "", target).split("/")[0]
    if target.count(":") == 1:  # « hote:port »
        target = target.split(":")[0]
    target = target.strip("[]")
    try:
        return str(ipaddress.ip_address(target)), None
    except ValueError:
        ip = socket.gethostbyname(target)  # accepte aussi un nom de domaine
        print(f"  {target} → {ip}")
        return ip, target.lower()


def resolve_target(target: str) -> str:
    return resolve(target)[0]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=f"{APP} — rapport HTML complet sur une adresse IP")
    ap.add_argument("ip", nargs="?", help="adresse IP (ou nom de domaine) à analyser")
    ap.add_argument("-p", "--ports", default="80,443", help="ports à analyser (défaut : 80,443)")
    ap.add_argument("-o", "--out", default=os.path.join(BASE_DIR, "rapports"), help="dossier de sortie")
    ap.add_argument("--no-screenshot", action="store_true", help="ne pas faire de capture d'écran")
    ap.add_argument("--offline", action="store_true", help="pas de requête vers les API en ligne")
    ap.add_argument("--no-open", action="store_true", help="ne pas ouvrir le rapport à la fin")
    ap.add_argument("--update-db", action="store_true", help="télécharger les bases DB-IP lite")
    ap.add_argument("--setup", action="store_true",
                    help="installer le navigateur Chromium et les bases DB-IP")
    a = ap.parse_args(argv)

    if a.setup:
        install_chromium()
        update_db()
        print("\nInstallation terminée.")
        return 0
    if a.update_db:
        update_db()
        if not a.ip:
            return 0
    if not a.offline:
        ensure_db()

    print(f"\n=== {APP} {VERSION} ===")
    target = a.ip or input("Adresse IP à analyser : ")
    try:
        ip, hostname = resolve(target)
    except (OSError, ValueError):
        print(f"Adresse invalide : {target!r}")
        return 2
    ports = parse_ports(a.ports)
    ipobj = ipaddress.ip_address(ip)
    if ipobj.is_private or ipobj.is_loopback:
        print("  (adresse privée : les sources Internet ne renverront rien d'utile)")

    print(f"\nAnalyse de {ip}\n")
    r = investigate(ip, ports, a.out, do_shot=not a.no_screenshot, offline=a.offline,
                    hostname=hostname)

    base = save_report(r, a.out)

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
