import requests
import urllib3
from dataclasses import dataclass, field
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Fuerza HTTPS en el navegador (HSTS)",
        "weight": 20,
        "recommended": "max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "description": "Previene XSS y code injection",
        "weight": 25,
        "recommended": "default-src 'self'"
    },
    "X-Frame-Options": {
        "description": "Previene Clickjacking",
        "weight": 15,
        "recommended": "DENY o SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "description": "Previene MIME-type sniffing",
        "weight": 10,
        "recommended": "nosniff"
    },
    "Referrer-Policy": {
        "description": "Controla info enviada en cabecera Referer",
        "weight": 10,
        "recommended": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "description": "Controla acceso a APIs del navegador",
        "weight": 10,
        "recommended": "geolocation=(), microphone=(), camera=()"
    },
    "X-XSS-Protection": {
        "description": "Protección XSS en navegadores antiguos",
        "weight": 10,
        "recommended": "1; mode=block"
    },
}

@dataclass
class HeaderResult:
    name: str
    present: bool
    value: Optional[str]
    description: str
    recommended: str
    weight: int

@dataclass
class HTTPResult:
    domain: str
    url: str = ""
    status_code: int = 0
    https_enabled: bool = False
    headers_found: list = field(default_factory=list)
    headers_missing: list = field(default_factory=list)
    server_info: Optional[str] = None
    score: int = 0
    error: Optional[str] = None

def scan_http(domain: str) -> HTTPResult:
    """Analiza los headers HTTP de seguridad de un dominio."""
    print(f"  [HTTP] Escaneando headers de {domain}...")

    result = HTTPResult(domain=domain)
    url = f"https://{domain}"
    result.url = url

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Security Scanner)"}
        )

        result.status_code = response.status_code
        result.https_enabled = response.url.startswith("https://")
        result.server_info = response.headers.get("Server", "Not disclosed")

        score = 0
        if result.https_enabled:
            score += 10

        for header_name, meta in SECURITY_HEADERS.items():
            value = response.headers.get(header_name)
            header_result = HeaderResult(
                name=header_name,
                present=value is not None,
                value=value,
                description=meta["description"],
                recommended=meta["recommended"],
                weight=meta["weight"]
            )

            if value is not None:
                result.headers_found.append(header_result)
                score += meta["weight"]
            else:
                result.headers_missing.append(header_result)

        result.score = min(score, 100)

    except requests.exceptions.SSLError:
        result.error = "SSL Certificate Error"
        result.https_enabled = False
    except requests.exceptions.ConnectionError:
        result.error = "No se pudo conectar al dominio"
    except requests.exceptions.Timeout:
        result.error = "Timeout - el servidor tardó demasiado"
    except Exception as e:
        result.error = str(e)

    return result