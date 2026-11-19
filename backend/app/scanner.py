from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

from .config import settings


class UnsafeTarget(ValueError):
    pass


def normalize_target(raw_url: str) -> tuple[str, str]:
    """Normalize a public HTTP(S) URL to its origin; discard path and query."""
    try:
        parsed = urlsplit(raw_url.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise UnsafeTarget("أدخل عنوانًا كاملًا يبدأ بـ http:// أو https://")
        if parsed.username is not None or parsed.password is not None:
            raise UnsafeTarget("لا يُسمح ببيانات مستخدم داخل العنوان")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if host in {"localhost", "localhost.localdomain"} or "." not in host or host.endswith(".local"):
            raise UnsafeTarget("يُسمح بالنطاقات العامة فقط")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise UnsafeTarget("أدخل اسم نطاق عام بدل عنوان IP مباشر")
        port = parsed.port
        expected_port = 443 if parsed.scheme.lower() == "https" else 80
        if port not in (None, expected_port):
            raise UnsafeTarget("المنافذ المخصصة غير مدعومة")
        return f"{parsed.scheme.lower()}://{host}", host
    except UnsafeTarget:
        raise
    except (UnicodeError, ValueError) as exc:
        raise UnsafeTarget("عنوان غير صالح") from exc


class PublicOnlyResolver(AbstractResolver):
    """Resolve hosts for aiohttp and reject any non-public result before connecting."""

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        try:
            literal = ipaddress.ip_address(host)
            addresses = [(socket.AF_INET6 if literal.version == 6 else socket.AF_INET, str(literal))]
        except ValueError:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys((item[0], item[4][0]) for item in infos))
        if not addresses:
            raise OSError("تعذر حل اسم النطاق")
        records = []
        for address_family, address in addresses:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
            if not parsed.is_global:
                raise OSError("تم حظر عنوان شبكة غير عامة")
            records.append({"hostname": host, "host": address, "port": port,
                            "family": address_family, "proto": 0,
                            "flags": socket.AI_NUMERICHOST})
        return records

    async def close(self) -> None:
        return None


async def fetch_headers(origin: str) -> tuple[int, dict[str, str]]:
    timeout = aiohttp.ClientTimeout(total=settings.scan_timeout_seconds, connect=4, sock_read=3)
    connector = aiohttp.TCPConnector(resolver=PublicOnlyResolver(), use_dns_cache=False, limit=1, ssl=True)
    headers = {"User-Agent": "DeraPassiveSecurityCheck/0.1 (+passive HEAD request)"}
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers,
                                     trust_env=False, auto_decompress=False) as session:
        async with session.head(origin + "/", allow_redirects=False, max_redirects=0) as response:
            return response.status, {key.lower(): value for key, value in response.headers.items()}
