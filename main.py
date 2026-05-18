import argparse
import sys
from colorama import init, Fore, Style

from scanner.dns_checker import scan_dns
from scanner.http_checker import scan_http
from scanner.subdomain_checker import scan_subdomains
from report.pdf_generator import generate_pdf

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║   
██║   ██║╚════██║██║██║╚██╗██║   ██║   
╚██████╔╝███████║██║██║ ╚████║   ██║   
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝  
{Fore.BLUE} Security Compliance Scanner — by VladimirRamirez07
{Fore.WHITE} 100% legal | Public DNS & HTTP data only
{Style.RESET_ALL}
"""

def print_section(title: str):
    print(f"\n{Fore.CYAN}{'─'*50}")
    print(f" {title}")
    print(f"{'─'*50}{Style.RESET_ALL}")

def print_score(label: str, score: int):
    if score >= 75:
        color = Fore.GREEN
        status = "GOOD"
    elif score >= 45:
        color = Fore.YELLOW
        status = "REGULAR"
    else:
        color = Fore.RED
        status = "CRITICAL"
    print(f"  {label}: {color}{score}/100 [{status}]{Style.RESET_ALL}")

def scan_domain(domain: str):
    print(BANNER)
    print(f"{Fore.WHITE}🎯 Target: {Fore.CYAN}{domain}{Style.RESET_ALL}")

    # ── DNS ──────────────────────────────────────────
    print_section("📧 DNS Security (SPF / DKIM / DMARC)")
    dns_result = scan_dns(domain)

    print(f"  SPF  : {Fore.GREEN+'✓ '+dns_result.spf[:60] if dns_result.spf else Fore.RED+'✗ Not found'}{Style.RESET_ALL}")
    print(f"  DKIM : {Fore.GREEN+'✓ Found' if dns_result.dkim else Fore.RED+'✗ Not found'}{Style.RESET_ALL}")
    print(f"  DMARC: {Fore.GREEN+'✓ '+dns_result.dmarc[:60] if dns_result.dmarc else Fore.RED+'✗ Not found'}{Style.RESET_ALL}")
    print(f"  DMARC Policy: {Fore.YELLOW}{dns_result.dmarc_policy.upper()}{Style.RESET_ALL}")
    print_score("DNS Score", dns_result.score)

    # ── HTTP ─────────────────────────────────────────
    print_section("🌐 HTTP Security Headers")
    http_result = scan_http(domain)

    if http_result.error:
        print(f"  {Fore.RED}⚠ Error: {http_result.error}{Style.RESET_ALL}")
    else:
        print(f"  HTTPS   : {Fore.GREEN+'✓ Enabled' if http_result.https_enabled else Fore.RED+'✗ Disabled'}{Style.RESET_ALL}")
        print(f"  Server  : {Fore.YELLOW}{http_result.server_info}{Style.RESET_ALL}")
        print(f"\n  {Fore.GREEN}Headers presentes ({len(http_result.headers_found)}):{Style.RESET_ALL}")
        for h in http_result.headers_found:
            print(f"    ✓ {h.name}")
        print(f"\n  {Fore.RED}Headers faltantes ({len(http_result.headers_missing)}):{Style.RESET_ALL}")
        for h in http_result.headers_missing:
            print(f"    ✗ {h.name} — {h.description}")
    print_score("HTTP Score", http_result.score)

    # ── SUBDOMINIOS ───────────────────────────────────
    print_section("🔎 Subdomain Enumeration & Takeover")
    sub_result = scan_subdomains(domain)

    print(f"  Verificados : {sub_result.total_checked}")
    print(f"  Encontrados : {Fore.CYAN}{len(sub_result.found)}{Style.RESET_ALL}")

    if sub_result.found:
        print(f"\n  {Fore.CYAN}Subdominios activos:{Style.RESET_ALL}")
        for s in sub_result.found:
            risk = f"{Fore.RED} ⚠ TAKEOVER RISK ({s.takeover_service})" if s.takeover_risk else ""
            print(f"    → {s.full_domain} [{s.ip}] HTTP:{s.http_status}{risk}{Style.RESET_ALL}")

    if sub_result.vulnerable:
        print(f"\n  {Fore.RED}🚨 Vulnerables a Takeover: {len(sub_result.vulnerable)}{Style.RESET_ALL}")
    print_score("Subdomain Score", sub_result.score)

    # ── SCORE FINAL ───────────────────────────────────
    overall = round((dns_result.score + http_result.score + sub_result.score) / 3)
    print_section("📊 Overall Security Score")
    print_score(f"  {domain}", overall)

    # ── PDF ───────────────────────────────────────────
    print_section("📄 Generating PDF Report")
    pdf_path = generate_pdf(domain, dns_result, http_result, sub_result)
    print(f"\n  {Fore.GREEN}✓ Report saved: {pdf_path}{Style.RESET_ALL}\n")

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Security Scanner — Analyzes public security of domains",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "domains",
        nargs="+",
        help="One or more domains to scan\nExample: python main.py apple.com netflix.com"
    )
    args = parser.parse_args()

    for domain in args.domains:
        domain = domain.lower().strip()
        print(f"\n{'═'*55}")
        scan_domain(domain)
        print(f"{'═'*55}\n")

if __name__ == "__main__":
    main()