import dns.resolver
import requests
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

# Subdominios comunes a verificar
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "test", "portal", "admin", "beta", "cdn", "cloud", "help", "support",
    "status", "static", "assets", "img", "images", "media", "upload",
    "downloads", "old", "new", "demo", "app", "mobile", "ww2", "preview",
]

# Patrones que indican posible Subdomain Takeover
TAKEOVER_SIGNATURES = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "amazonaws.com": "NoSuchBucket",
    "fastly.net": "Fastly error: unknown domain",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "zendesk.com": "Help Center Closed",
    "ghost.io": "The thing you were looking for is no longer here",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "azurewebsites.net": "404 Web Site not found",
}

@dataclass
class SubdomainResult:
    subdomain: str
    full_domain: str
    resolves: bool = False
    ip: str = ""
    cname: str = ""
    http_status: int = 0
    takeover_risk: bool = False
    takeover_service: str = ""
    takeover_reason: str = ""

@dataclass
class SubdomainScanResult:
    domain: str
    found: list = field(default_factory=list)
    vulnerable: list = field(default_factory=list)
    total_checked: int = 0
    score: int = 100  # Empieza en 100, baja por vulnerabilidades

def check_single_subdomain(subdomain: str, domain: str) -> SubdomainResult:
    """Verifica un único subdominio."""
    full_domain = f"{subdomain}.{domain}"
    result = SubdomainResult(subdomain=subdomain, full_domain=full_domain)

    # 1. Verificar si resuelve DNS
    try:
        answers = dns.resolver.resolve(full_domain, 'A')
        result.resolves = True
        result.ip = answers[0].to_text()
    except dns.resolver.NXDOMAIN:
        return result  # No existe
    except Exception:
        pass

    # 2. Buscar registro CNAME
    try:
        cname_answers = dns.resolver.resolve(full_domain, 'CNAME')
        result.cname = cname_answers[0].to_text()
    except Exception:
        pass

    # 3. Verificar respuesta HTTP y posible takeover
    if result.resolves or result.cname:
        try:
            response = requests.get(
                f"https://{full_domain}",
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Security Scanner)"}
            )
            result.http_status = response.status_code
            body = response.text.lower()

            # Verificar firmas de takeover
            for service, signature in TAKEOVER_SIGNATURES.items():
                if signature.lower() in body:
                    result.takeover_risk = True
                    result.takeover_service = service
                    result.takeover_reason = signature
                    break

        except Exception:
            # Intentar HTTP si HTTPS falla
            try:
                response = requests.get(
                    f"http://{full_domain}",
                    timeout=5,
                    allow_redirects=True
                )
                result.http_status = response.status_code
            except Exception:
                pass

    return result

def scan_subdomains(domain: str, max_workers: int = 20) -> SubdomainScanResult:
    """
    Escanea subdominios comunes en paralelo usando ThreadPoolExecutor.
    Más rápido que hacerlo uno por uno.
    """
    print(f"  [SUBDOMAIN] Escaneando {len(COMMON_SUBDOMAINS)} subdominios de {domain}...")

    scan_result = SubdomainScanResult(domain=domain)
    scan_result.total_checked = len(COMMON_SUBDOMAINS)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_single_subdomain, sub, domain): sub
            for sub in COMMON_SUBDOMAINS
        }

        for future in as_completed(futures):
            try:
                result = future.result()
                if result.resolves or result.cname:
                    scan_result.found.append(result)
                    if result.takeover_risk:
                        scan_result.vulnerable.append(result)
                        scan_result.score -= 25  # Penalización por vulnerabilidad
            except Exception:
                continue

    scan_result.score = max(scan_result.score, 0)
    return scan_result