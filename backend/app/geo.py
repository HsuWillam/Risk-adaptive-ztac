"""
Geolocation helper — resolves a client IP to coordinates for the I (location)
and G (geo-velocity) risk factors.

Layered, same policy as the monolith build:
  1. GeoLite2 (MaxMind) local .mmdb   — fast/offline, cached Reader (opened once).
  2. ip-api.com HTTP fallback         — for online deploys (Render) with no .mmdb.
  3. Dev fallback coordinates         — private/localhost IPs only.

Private / loopback / reserved IPs resolve to no real signal so localhost is not
penalised. `client_ip()` extracts the true client behind a reverse proxy.
"""
import ipaddress
import logging

import requests

import config

log = logging.getLogger(__name__)

_reader = None
_reader_state = "unopened"     # unopened | ready | missing
_http_cache = {}


def client_ip(request) -> str:
    """Leftmost X-Forwarded-For entry is the real client behind Render's proxy."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def is_routable(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_reserved or a.is_multicast)


def _get_reader():
    global _reader, _reader_state
    if _reader_state == "ready":
        return _reader
    if _reader_state == "missing":
        return None
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(config.GEOIP_DB_PATH)
        _reader_state = "ready"
        log.info("GeoLite2 loaded from %s", config.GEOIP_DB_PATH)
        return _reader
    except Exception as exc:
        _reader_state = "missing"
        log.warning("GeoLite2 unavailable (%s); using HTTP/dev fallback.", exc)
        return None


def _geolite_lookup(ip: str):
    reader = _get_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
    except Exception:
        return None
    if r.location.latitude is None or r.location.longitude is None:
        return None
    return (float(r.location.latitude), float(r.location.longitude))


def _http_lookup(ip: str):
    if ip in _http_cache:
        return _http_cache[ip]
    result = None
    try:
        resp = requests.get(config.GEOIP_HTTP_URL.format(ip=ip),
                            timeout=config.GEOIP_HTTP_TIMEOUT)
        data = resp.json()
        if data.get("status") == "success":
            result = (data["lat"], data["lon"])
    except Exception:
        result = None
    _http_cache[ip] = result
    return result


def geolocate(ip: str):
    """Return (lat, lon) or (None, None)."""
    if is_routable(ip):
        loc = _geolite_lookup(ip)                       # 1. local DB
        if loc is not None:
            return loc
        if getattr(config, "GEOIP_HTTP_FALLBACK", True):  # 2. ip-api.com
            loc = _http_lookup(ip)
            if loc is not None:
                return loc
        return (None, None)
    fallback = getattr(config, "GEOIP_DEV_FALLBACK_LATLON", None)  # 3. private/dev
    if fallback:
        return fallback
    return (None, None)
