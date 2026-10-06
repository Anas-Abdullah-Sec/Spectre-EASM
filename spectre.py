import sys
import json
import asyncio
import argparse
import aiohttp
from typing import List, Set, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt

# ==============================================================================
#  SPECTRE EASM - External Attack Surface Manager & Risk Auditor
#  Developer : Anas Abdullah
#  LinkedIn  : https://www.linkedin.com/in/anas-abdullah/
# ==============================================================================

console = Console()

BANNER = """[bold green]
███████╗██████╗ ███████╗██████╗████████╗██████╗ ███████╗
██╔════╝██╔══██╗██╔════╝██╔════╝   ██╔══╝██╔══██╗██╔════╝
███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝[/bold green]
[dim green]──────────────────────────────────────────────────────────────────[/dim green]
[bold white] Tool Name   :[bold green] SpectreEASM [dim](Attack Surface Management Engine)[/dim]
[bold white] Developer   :[bold green] Anas Abdullah
[bold white] LinkedIn    :[bold cyan] https://www.linkedin.com/in/anas-abdullah/
[dim green]──────────────────────────────────────────────────────────────────[/dim green]
"""

# --- MODULE 1: SUBDOMAIN ENUMERATION ENGINE ---
class SubdomainEnumerator:
    def __init__(self, domain: str, timeout: int = 10):
        self.domain = domain
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.headers = {"User-Agent": "SpectreEASM/2.0 (Security Audit Framework)"}

    async def _fetch_crt_sh(self, session: aiohttp.ClientSession) -> Set[str]:
        discovered = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with session.get(url, headers=self.headers, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json(content_type=None)
                    for entry in data:
                        for d in entry.get("name_value", "").split("\n"):
                            d = d.strip().lower()
                            if d.startswith("*."):
                                d = d[2:]
                            if d.endswith(self.domain) and d != self.domain:
                                discovered.add(d)
        except Exception:
            pass
        return discovered

    async def _fetch_hackertarget(self, session: aiohttp.ClientSession) -> Set[str]:
        discovered = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with session.get(url, headers=self.headers, timeout=self.timeout) as response:
                if response.status == 200:
                    text = await response.text()
                    for line in text.splitlines():
                        if "," in line:
                            hostname = line.split(",")[0].strip().lower()
                            if hostname.endswith(self.domain) and hostname != self.domain:
                                discovered.add(hostname)
        except Exception:
            pass
        return discovered

    async def enumerate_all(self) -> List[str]:
        async with aiohttp.ClientSession() as session:
            tasks = [self._fetch_crt_sh(session), self._fetch_hackertarget(session)]
            results = await asyncio.gather(*tasks)
            unique: Set[str] = set()
            for res in results:
                unique.update(res)
            return sorted(list(unique))


# --- MODULE 2: ASSET FINGERPRINTER & HEADER AUDITOR ---
class AssetFingerprinter:
    def __init__(self, timeout: int = 5):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.headers_to_check = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-Content-Type-Options"
        ]

    async def scan_asset(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        target_url = f"https://{url}"
        asset_data = {
            "target": url,
            "status_code": None,
            "server": "Unknown",
            "missing_headers": [],
            "error": None
        }
        try:
            async with session.get(target_url, timeout=self.timeout, ssl=False) as response:
                asset_data["status_code"] = response.status
                asset_data["server"] = response.headers.get("Server", "Hidden/Unknown")
                
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                for h in self.headers_to_check:
                    if h.lower() not in resp_headers:
                        asset_data["missing_headers"].append(h)
        except asyncio.TimeoutError:
            asset_data["error"] = "Timeout"
        except Exception:
            asset_data["error"] = "Unreachable"

        return asset_data


# --- MODULE 3: ACCURATE RISK ENGINE ---
class RiskEngine:
    @staticmethod
    def evaluate(asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates accurate risk scores based on operational status."""
        score = 0.0
        findings = []
        status = asset_data.get("status_code")

        # 1. Unreachable / Timeout Assets
        if asset_data.get("error"):
            return {"score": 0.0, "severity": "INFORMATIONAL", "findings": ["Unreachable Target"]}

        # 2. Non-200 Status Codes (e.g., 404 Not Found, 403 Forbidden) -> Low Risk Penalty
        if status in [404, 410]:
            return {"score": 0.5, "severity": "LOW", "findings": [f"Status {status} (Asset Inactive/Missing)"]}
        elif status in [401, 403]:
            return {"score": 1.5, "severity": "LOW", "findings": [f"Status {status} (Access Restricted)"]}
        elif status and status >= 500:
            return {"score": 3.0, "severity": "MEDIUM", "findings": [f"Status {status} (Internal Server Error)"]}

        # 3. Active 200 OK Assets -> Audit Missing Security Headers
        missing = asset_data.get("missing_headers", [])
        if "Strict-Transport-Security" in missing:
            score += 2.5
            findings.append("Missing HSTS Policy")
        if "Content-Security-Policy" in missing:
            score += 2.5
            findings.append("Missing Content-Security-Policy")
        if "X-Frame-Options" in missing:
            score += 1.5
            findings.append("Missing Clickjacking Protection")
        if "X-Content-Type-Options" in missing:
            score += 0.5
            findings.append("Missing MIME Sniffing Protection")

        score = min(round(score, 1), 10.0)
        if score >= 7.0:
            severity = "CRITICAL"
        elif score >= 5.0:
            severity = "HIGH"
        elif score >= 2.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {"score": score, "severity": severity, "findings": findings}


# --- MAIN ENGINE CONTROLLER ---
async def run_spectre(target_domain: str, output_file: str = None):
    console.clear()
    console.print(BANNER)
    console.print(f"[bold green][*] Target Domain:[bold white] {target_domain}\n")

    # Step 1: Subdomain Discovery with Progress Spinner
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold green]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Enumerating Passive Attack Surface...", total=None)
        enumerator = SubdomainEnumerator(target_domain)
        subdomains = await enumerator.enumerate_all()

    if not subdomains:
        console.print(f"[bold red][!] No passive subdomains discovered. Auditing base domain only.[/bold red]")
        subdomains = [target_domain]
    else:
        console.print(f"[bold green][+] Discovered [bold white]{len(subdomains)}[/bold white] Attack Surface Assets.[/bold green]\n")

    # Step 2: Async Fingerprinting
    fingerprinter = AssetFingerprinter()
    final_report = []

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold green]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Auditing Assets & Evaluating Security Risk Scores...", total=None)
        async with aiohttp.ClientSession() as session:
            tasks = [fingerprinter.scan_asset(session, sub) for sub in subdomains]
            results = await asyncio.gather(*tasks)

    # Step 3: Render Rich UI Table
    table = Table(title=f"Attack Surface Assessment Report - {target_domain}", border_style="green", header_style="bold green")
    table.add_column("Asset Domain", style="bold white", justify="left")
    table.add_column("HTTP Status", justify="center")
    table.add_column("Risk Score", justify="center")
    table.add_column("Severity Level", justify="center")
    table.add_column("Primary Vulnerability/Finding", justify="left")

    for res in results:
        risk = RiskEngine.evaluate(res)
        combined = {**res, "risk_assessment": risk}
        final_report.append(combined)

        # Format Status Badges
        st = res['status_code']
        if st == 200:
            status_str = f"[bold green]{st} OK[/bold green]"
        elif st in [404, 403, 401]:
            status_str = f"[bold yellow]{st}[/bold yellow]"
        elif res['error']:
            status_str = f"[bold red]{res['error']}[/bold red]"
        else:
            status_str = f"[white]{st}[/white]"

        # Format Severity Colors
        sev = risk['severity']
        score_str = f"{risk['score']}"
        if sev == "CRITICAL":
            sev_str = f"[bold red]{sev}[/bold red]"
            score_str = f"[bold red]{score_str}[/bold red]"
        elif sev == "HIGH":
            sev_str = f"[bold red]{sev}[/bold red]"
            score_str = f"[bold red]{score_str}[/bold red]"
        elif sev == "MEDIUM":
            sev_str = f"[bold yellow]{sev}[/bold yellow]"
            score_str = f"[bold yellow]{score_str}[/bold yellow]"
        else:
            sev_str = f"[green]{sev}[/green]"
            score_str = f"[green]{score_str}[/green]"

        findings_summary = ", ".join(risk['findings']) if risk['findings'] else "No Critical Issues"
        table.add_row(res['target'], status_str, score_str, sev_str, findings_summary)

    console.print(table)

    # Step 4: Export to JSON
    if output_file:
        with open(output_file, "w") as f:
            json.dump(final_report, f, indent=4)
        console.print(f"\n[bold green][+] Assessment Report exported successfully to:[/bold green] [bold cyan]{output_file}[/bold cyan]")


def main():
    parser = argparse.ArgumentParser(description="SpectreEASM - External Attack Surface Management Engine")
    parser.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Output file path for JSON report (e.g. report.json)")
    args = parser.parse_args()

    # Interactive Prompt Mode if no domain parameter passed
    target = args.domain
    output = args.output

    if not target:
        console.clear()
        console.print(BANNER)
        target = Prompt.ask("[bold green][?] Enter Target Domain (e.g. example.com)[/bold green]")
        if not target.strip():
            console.print("[bold red][!] Target domain cannot be empty. Exiting.[/bold red]")
            sys.exit(1)
        
        save_opt = Prompt.ask("[bold green][?] Save JSON report? (y/n)[/bold green]", default="y")
        if save_opt.lower() == "y":
            output = f"{target.replace('.', '_')}_easm_report.json"

    asyncio.run(run_spectre(target, output))


if __name__ == "__main__":
    main()