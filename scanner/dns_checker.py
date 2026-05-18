import dns.resolver
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class DNSResult:
    domain: str
    spf: Optional[str] = None
    spf_valid: bool = False
    dkim: Optional[str] = None
    dkim_valid: bool = False
    dmarc: Optional[str] = None
    dmarc_valid: bool = False
    dmarc_policy: str = "none"
    errors: list = field(default_factory=list)
    score: int = 0

def check_spf(domain: str) -> tuple[Optional[str], bool]:
    """Busca y valida el registro SPF del dominio."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for record in answers:
            txt = record.to_text().strip('"')
            if txt.startswith('v=spf1'):
                is_valid = '-all' in txt or '~all' in txt
                return txt, is_valid
        return None, False
    except Exception as e:
        return None, False

def check_dkim(domain: str, selector: str = "default") -> tuple[Optional[str], bool]:
    """
    Busca el registro DKIM. Prueba selectores comunes
    ya que el selector varía por empresa.
    """
    selectors = [selector, "google", "mail", "dkim", "k1", "selector1", "selector2"]
    for sel in selectors:
        try:
            dkim_domain = f"{sel}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for record in answers:
                txt = record.to_text().strip('"')
                if 'v=DKIM1' in txt or 'p=' in txt:
                    return txt, True
        except Exception:
            continue
    return None, False

def check_dmarc(domain: str) -> tuple[Optional[str], bool, str]:
    """Busca y analiza el registro DMARC del dominio."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for record in answers:
            txt = record.to_text().strip('"')
            if txt.startswith('v=DMARC1'):
                # Extraer política
                policy = "none"
                for part in txt.split(';'):
                    part = part.strip()
                    if part.startswith('p='):
                        policy = part.split('=')[1].strip()
                is_valid = policy in ['quarantine', 'reject']
                return txt, is_valid, policy
        return None, False, "none"
    except Exception:
        return None, False, "none"

def calculate_score(result: DNSResult) -> int:
    """Calcula un score de 0-100 basado en los resultados DNS."""
    score = 0
    if result.spf:
        score += 20
    if result.spf_valid:
        score += 15
    if result.dkim_valid:
        score += 25
    if result.dmarc:
        score += 15
    if result.dmarc_policy == 'quarantine':
        score += 15
    elif result.dmarc_policy == 'reject':
        score += 25
    return min(score, 100)

def scan_dns(domain: str) -> DNSResult:
    """Función principal: escanea todos los registros DNS de seguridad."""
    print(f"  [DNS] Escaneando {domain}...")
    result = DNSResult(domain=domain)

    result.spf, result.spf_valid = check_spf(domain)
    result.dkim, result.dkim_valid = check_dkim(domain)
    result.dmarc, result.dmarc_valid, result.dmarc_policy = check_dmarc(domain)
    result.score = calculate_score(result)

    return result