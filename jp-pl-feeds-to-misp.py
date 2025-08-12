import io
import re
import time
import html
import requests
import feedparser
from typing import List, Dict, Set
from datetime import datetime, timezone
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, urljoin
from pymisp import PyMISP, MISPEvent, MISPAttribute
import urllib3


MISP_URL = ""
MISP_KEY = "YOUR_MISP_API_KEY"
MISP_VERIFY_CERT = False          # you're using self-signed in your lab

STRICT_VT_GATE = False            # False -> ingest all unique (recommended to see values first)

VT_API_KEY = ""                   # optional; set to enable strict VT gating


# Silence HTTPS verification warnings for your lab MISP
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HTTP / parsing
USER_AGENT = "cert-feeds-to-misp/4.0 (+MISP; CTI Collector)"
REQ_TIMEOUT = 45
RSS_LIMIT_PER_FEED = 100
ARTICLE_MAX_BYTES = 2_000_000
PDF_MAX_PAGES = 12
CRAWL_ARTICLE = True
FOLLOW_SECOND_HOP = True
DEFAULT_TLP = "tlp:white"         # keep tlp:white; script will set distribution=3 to match

# VirusTotal
VT_HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
VT_URLS = {
    "submit_url": "https://www.virustotal.com/api/v3/urls",
    "analyses":   "https://www.virustotal.com/api/v3/analyses/",
    "domain":     "https://www.virustotal.com/api/v3/domains/",
    "ip":         "https://www.virustotal.com/api/v3/ip_addresses/",
    "file":       "https://www.virustotal.com/api/v3/files/",
}

# ---------- CURATED FEEDS (IOC-producing) ----------
FEEDS: List[Dict] = [
    {"name": "JPCERT/CC",      "country": "JP", "urls": ["https://www.jpcert.or.jp/rss/jpcert.rdf"], "auth": {"type": "none"}},
    {"name": "CERT-PL (EN)",   "country": "PL", "urls": ["https://cert.pl/en/feed/"],               "auth": {"type": "none"}},
    {"name": "CERT-PL (PL)",   "country": "PL", "urls": ["https://cert.pl/feed/"],                  "auth": {"type": "none"}},
]

# =========== IOC extraction ===========
URL_RE   = r'https?://[^\s\)\]"\'>]+'
IPV4_RE  = r'(?:\d{1,3}\.){3}\d{1,3}'
DOM_RE   = r'[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
MD5_RE   = r'\b[a-fA-F0-9]{32}\b'
SHA1_RE  = r'\b[a-fA-F0-9]{40}\b'
SHA256_RE= r'\b[a-fA-F0-9]{64}\b'
IOC_REGEX = re.compile(r'(' + '|'.join([URL_RE, IPV4_RE, DOM_RE, MD5_RE, SHA1_RE, SHA256_RE]) + r')')
TRAILING_PUNCT = '.,;:)]}>"\''

def defang_to_plain(s: str) -> str:
    s = (s or "")
    return (s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
            .replace("hxxp://", "http://").replace("hxxps://", "https://"))

def normalize_url(u: str) -> str:
    u = defang_to_plain(u.strip())
    while u and u[-1] in TRAILING_PUNCT: u = u[:-1]
    u = html.unescape(u)
    try:
        p = urlparse(u)
        if p.scheme in ("http", "https") and p.netloc: return u
    except Exception: pass
    return ""

def normalize_domain(d: str) -> str:
    d = defang_to_plain(d.strip().lower())
    while d and d[-1] in TRAILING_PUNCT: d = d[:-1]
    if "." not in d or len(d.split(".")[-1]) < 2: return ""
    if d.startswith("http:") or d.startswith("https:"): return ""
    return d

def normalize_ip(ip: str) -> str:
    ip = defang_to_plain(ip.strip())
    return ip if re.fullmatch(IPV4_RE, ip) else ""

def normalize_hash(h: str) -> str:
    h = (h or "").strip().lower()
    if re.fullmatch(MD5_RE, h) or re.fullmatch(SHA1_RE, h) or re.fullmatch(SHA256_RE, h): return h
    return ""

def extract_and_normalize_iocs(text: str) -> Set[str]:
    out: Set[str] = set()
    if not text: return out
    for raw in IOC_REGEX.findall(text):
        raw = html.unescape(raw)
        if raw.lower().startswith("http"):
            u = normalize_url(raw);      out.add(u)   if u else None
        elif re.fullmatch(IPV4_RE, raw):
            ip = normalize_ip(raw);      out.add(ip)  if ip else None
        elif re.fullmatch(MD5_RE, raw) or re.fullmatch(SHA1_RE, raw) or re.fullmatch(SHA256_RE, raw):
            hh = normalize_hash(raw);    out.add(hh)  if hh else None
        else:
            dom = normalize_domain(raw); out.add(dom) if dom else None
    return out


def session_with_retries() -> requests.Session:
    s = requests.Session()
    retries = Retry(total=4, backoff_factor=0.7,
                    status_forcelist=(403,404,408,429,500,502,503,504),
                    allowed_methods=frozenset(["GET","POST"]))
    adapter = HTTPAdapter(max_retries=retries, pool_maxsize=20)
    s.mount("https://", adapter); s.mount("http://", adapter)
    return s

SESSION = session_with_retries()

def build_kwargs(auth: Dict) -> Dict:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/rss+xml,application/atom+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8",
        "Cache-Control": "no-cache", "Pragma": "no-cache",
    }
    kwargs: Dict = {"timeout": REQ_TIMEOUT, "verify": True, "headers": headers, "allow_redirects": True}
    t = (auth or {}).get("type", "none").lower()
    if t == "basic":
        kwargs["auth"] = HTTPBasicAuth(auth.get("username") or "", auth.get("password") or "")
    elif t == "bearer":
        headers["Authorization"] = f"Bearer {auth.get('token','')}"
    elif t == "mtls":
        cert_tuple = auth.get("cert")
        if cert_tuple and isinstance(cert_tuple, tuple) and all(cert_tuple): kwargs["cert"] = cert_tuple
    return kwargs

def fetch_rss_entries(feed: Dict, limit: int) -> List[dict]:
    for u in feed.get("urls", []):
        try:
            r = SESSION.get(u, **build_kwargs(feed.get("auth"))); r.raise_for_status()
            parsed = feedparser.parse(r.content)
            entries = parsed.entries[:limit] if parsed.entries else []
            if not entries:
                parsed = feedparser.parse(u)
                entries = parsed.entries[:limit] if parsed.entries else []
            if entries: return entries
        except Exception:
            time.sleep(0.4); continue
    return []

def html_text_only(content: bytes) -> str:
    try: text = content.decode("utf-8", errors="ignore")
    except Exception: text = str(content)
    text = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text)

def is_pdf_response(r: requests.Response, url: str) -> bool:
    ct = (r.headers.get("Content-Type") or "").lower()
    return ("application/pdf" in ct) or url.lower().endswith(".pdf")

def fetch_article_text(url: str, auth: Dict) -> str:
    try:
        with SESSION.get(url, stream=True, **build_kwargs(auth)) as r:
            r.raise_for_status()
            raw = io.BytesIO()
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk: break
                raw.write(chunk)
                if raw.tell() > ARTICLE_MAX_BYTES: break
            data = raw.getvalue()
            if is_pdf_response(r, url): return pdf_to_text(data)
            return html_text_only(data)
    except Exception:
        return ""

def fetch_article_text_follow(url: str, auth: Dict) -> str:
    txt = fetch_article_text(url, auth)
    if txt or not FOLLOW_SECOND_HOP: return txt
    try:
        r = SESSION.get(url, **build_kwargs(auth)); r.raise_for_status()
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', r.text, flags=re.I)
        for h in hrefs[:20]:
            if not h: continue
            if not h.startswith("http"): h = urljoin(url, h)
            if h.lower().endswith(".pdf") or "/advisories/" in h or "/alerts/" in h:
                t2 = fetch_article_text(h, auth)
                if t2: return t2
    except Exception:
        pass
    return ""

def pdf_to_text(data: bytes) -> str:
    try:
        import pdfminer.high_level
        from pdfminer.layout import LAParams
        out = io.StringIO()
        pdfminer.high_level.extract_text_to_fp(io.BytesIO(data), outfp=out, laparams=LAParams(), maxpages=PDF_MAX_PAGES)
        return re.sub(r"\s+", " ", out.getvalue())
    except Exception:
        return ""

def entry_text_blobs(entry: dict) -> str:
    parts = []
    for k in ("title", "summary", "description"):
        v = entry.get(k)
        if v: parts.append(html.unescape(v))
    if "content" in entry and isinstance(entry["content"], list):
        for c in entry["content"]:
            v = c.get("value"); 
            if v: parts.append(html.unescape(v))
    sd = entry.get("summary_detail", {})
    if isinstance(sd, dict) and sd.get("value"): parts.append(html.unescape(sd["value"]))
    return "\n".join(parts)

# =========== VirusTotal ===========
def vt_stats_from_url(url: str) -> int:
    if not VT_API_KEY: return 0
    try:
        s = SESSION.post(VT_URLS["submit_url"], headers=VT_HEADERS, data={"url": url}, timeout=30)
        if s.status_code != 200: return 0
        vid = s.json().get("data", {}).get("id"); 
        if not vid: return 0
        a = SESSION.get(VT_URLS["analyses"] + vid, headers=VT_HEADERS, timeout=30)
        stats = a.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return int(stats.get("malicious", 0) or 0)
    except Exception:
        return 0

def vt_stats_from_domain(domain: str) -> int:
    if not VT_API_KEY: return 0
    try:
        r = SESSION.get(VT_URLS["domain"] + domain, headers=VT_HEADERS, timeout=30)
        if r.status_code != 200: return 0
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return int(stats.get("malicious", 0) or 0)
    except Exception:
        return 0

def vt_stats_from_ip(ip: str) -> int:
    if not VT_API_KEY: return 0
    try:
        r = SESSION.get(VT_URLS["ip"] + ip, headers=VT_HEADERS, timeout=30)
        if r.status_code != 200: return 0
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return int(stats.get("malicious", 0) or 0)
    except Exception:
        return 0

def vt_stats_from_hash(h: str) -> int:
    if not VT_API_KEY: return 0
    try:
        r = SESSION.get(VT_URLS["file"] + h, headers=VT_HEADERS, timeout=30)
        if r.status_code != 200: return 0
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return int(stats.get("malicious", 0) or 0)
    except Exception:
        return 0

def vt_is_malicious(ioc: str) -> bool:
    if not VT_API_KEY: return False
    if ioc.startswith("http"): return vt_stats_from_url(ioc) > 0
    if re.fullmatch(IPV4_RE, ioc): return vt_stats_from_ip(ioc) > 0
    if re.fullmatch(MD5_RE, ioc) or re.fullmatch(SHA1_RE, ioc) or re.fullmatch(SHA256_RE, ioc):
        return vt_stats_from_hash(ioc) > 0
    return vt_stats_from_domain(ioc) > 0

# =========== MISP ===========
def init_misp() -> PyMISP:
    return PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_CERT)

def misp_is_duplicate(misp: PyMISP, value: str) -> bool:
    try:
        res = misp.search(controller="attributes", value=value) or {}
        return bool(res.get("Attribute"))
    except Exception:
        return False

def misp_attr_type(value: str) -> str:
    if value.startswith("http"): return "url"
    if re.fullmatch(IPV4_RE, value): return "ip-dst"
    if re.fullmatch(SHA256_RE, value): return "sha256"
    if re.fullmatch(SHA1_RE, value): return "sha1"
    if re.fullmatch(MD5_RE, value): return "md5"
    return "domain"

def misp_ingest_event(misp: PyMISP, source_name: str, country: str, values: List[str]) -> None:
    if not values:
        print(f"[INFO] No malicious IOCs to ingest for {source_name}."); return
    evt = MISPEvent()
    # Title with country code (crystal clear)
    evt.info = f"{source_name} ({country}) – CERT feed ingestion – {datetime.now(timezone.utc):%Y-%m-%d}"
    # Match TLP policy to avoid warning: tlp:white => All communities(3); else community(1)
    evt.distribution = 3 if (DEFAULT_TLP and DEFAULT_TLP.lower().startswith("tlp:white")) else 1
    evt.analysis = 2            # Completed
    evt.threat_level_id = 2     # Medium
    evt.published = True        # Yes

    evt.add_tag("osint"); evt.add_tag("source:cert")
    evt.add_tag(f"country:{country}")
    evt.add_tag(f"feed:{source_name.lower().replace(' ', '_')}")
    if DEFAULT_TLP: evt.add_tag(DEFAULT_TLP)

    for v in sorted(set(values)):
        attr = MISPAttribute()
        attr.type = misp_attr_type(v); attr.value = v
        attr.comment = f"Source: {source_name}"
        evt.add_attribute(**attr)

    out = misp.add_event(evt)
    evt_id = (out or {}).get("Event", {}).get("id", "?")
    print(f"[INFO] Ingested {len(values)} attributes into MISP (event {evt_id}) from {source_name}")

# =========== Main ===========
def run():
    if not MISP_URL or not MISP_KEY:
        print("[INFO] Please set MISP_URL and MISP_KEY in the script."); return
    if STRICT_VT_GATE and not VT_API_KEY:
        print("[INFO] STRICT_VT_GATE=True but VT_API_KEY is empty. Set VT_API_KEY or switch to lenient mode."); return

    misp = init_misp()
    global_seen: Set[str] = set()

    for feed in FEEDS:
        name = feed.get("name", "Unknown Feed"); country = feed.get("country", "XX")
        print(f"\n[INFO] Pulling: {name} ({country})")
        entries = fetch_rss_entries(feed, limit=RSS_LIMIT_PER_FEED)

        collected: Set[str] = set()
        for e in entries:
            collected |= extract_and_normalize_iocs(entry_text_blobs(e))
            if CRAWL_ARTICLE:
                link = e.get("link")
                if link and isinstance(link, str):
                    txt = fetch_article_text_follow(link, feed.get("auth"))
                    if txt: collected |= extract_and_normalize_iocs(txt)
                    time.sleep(0.2)

        print(f"[INFO] Candidates extracted: {len(collected)}")

        # Global de-dup
        unique_new = [ioc for ioc in collected if ioc and ioc not in global_seen]
        for v in unique_new: global_seen.add(v)
        print(f"[INFO] After global de-dup (this run): {len(unique_new)}")

        # Skip existing in MISP
        not_in_misp: List[str] = []
        for ioc in unique_new:
            if not misp_is_duplicate(misp, ioc):
                not_in_misp.append(ioc)
        print(f"[INFO] Not present in MISP: {len(not_in_misp)}")

        # VT gating
        if STRICT_VT_GATE and VT_API_KEY:
            kept: List[str] = []
            for ioc in not_in_misp:
                if vt_is_malicious(ioc): kept.append(ioc)
                if len(kept) and len(kept) % 20 == 0: time.sleep(1)
        else:
            kept = not_in_misp[:]

        print(f"[INFO] Kept for ingest: {len(kept)} (mode: {'strict' if STRICT_VT_GATE else 'lenient'})")
        misp_ingest_event(misp, name, country, kept)
        time.sleep(0.5)

if __name__ == "__main__":
    run()
