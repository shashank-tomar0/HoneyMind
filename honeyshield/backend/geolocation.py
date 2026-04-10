"""
IP Geolocation Service
======================
Resolves IP addresses to geographic coordinates using the free ip-api.com service.
For localhost/private IPs, resolves the machine's public IP instead.
Results are cached to avoid repeated API calls.
"""

import logging
import requests
from functools import lru_cache

logger = logging.getLogger(__name__)

# Private IP ranges that can't be geolocated directly
_PRIVATE_PREFIXES = ("127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "0.", "::1", "localhost")

_public_ip_cache = None


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/localhost."""
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES)


def _get_public_ip() -> str:
    """Get this machine's public IP address."""
    global _public_ip_cache
    if _public_ip_cache:
        return _public_ip_cache
    try:
        resp = requests.get("https://api.ipify.org?format=json", timeout=3)
        _public_ip_cache = resp.json().get("ip", "")
        logger.info("Resolved public IP: %s", _public_ip_cache)
        return _public_ip_cache
    except Exception as e:
        logger.warning("Failed to resolve public IP: %s", e)
        return ""


@lru_cache(maxsize=256)
def geolocate_ip(ip: str) -> dict:
    """
    Resolve an IP address to geographic location.

    Returns dict with: lat, lng, country, country_code, city, isp, org
    Falls back to defaults if lookup fails.
    """
    lookup_ip = ip

    # For private/localhost IPs, use the machine's public IP
    if _is_private_ip(ip):
        lookup_ip = _get_public_ip()
        if not lookup_ip:
            return _default_geo()

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{lookup_ip}",
            params={"fields": "status,message,country,countryCode,city,lat,lon,isp,org,query"},
            timeout=3,
        )
        data = resp.json()

        if data.get("status") == "success":
            geo = {
                "lat": data.get("lat", 0),
                "lng": data.get("lon", 0),
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "XX"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "resolved_ip": data.get("query", lookup_ip),
            }
            logger.info("Geolocated %s -> %s, %s (%.2f, %.2f)",
                        ip, geo["city"], geo["country"], geo["lat"], geo["lng"])
            return geo
        else:
            logger.warning("Geolocation failed for %s: %s", lookup_ip, data.get("message"))
            return _default_geo()

    except Exception as e:
        logger.warning("Geolocation request failed for %s: %s", ip, e)
        return _default_geo()


def _default_geo() -> dict:
    """Fallback geolocation when lookup fails."""
    return {
        "lat": 20.59,
        "lng": 78.96,
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "isp": "",
        "org": "",
        "resolved_ip": "",
    }
