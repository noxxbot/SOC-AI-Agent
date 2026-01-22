import httpx
from typing import Dict, Any, Optional, List


class ThreatIntelSources:
    def __init__(self):
        # ✅ Existing (Working) Sources
        self.nvd_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        # ✅ NEW: AlienVault OTX (FREE) - for APT / Malware / Keyword intel
        self.otx_search_url = "https://otx.alienvault.com/api/v1/search/pulses"

    # ---------------------------------------------------------
    # ✅ Existing Working: NVD CVE Fetch
    # ---------------------------------------------------------
    async def fetch_nvd_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE details from NVD API.
        """
        params = {"cveId": cve_id}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(self.nvd_base, params=params)
                r.raise_for_status()
                data = r.json()

                if not data.get("vulnerabilities"):
                    return None

                vuln = data["vulnerabilities"][0]["cve"]
                descriptions = vuln.get("descriptions", [])
                description_text = ""

                for d in descriptions:
                    if d.get("lang") == "en":
                        description_text = d.get("value", "")
                        break

                metrics = vuln.get("metrics", {})
                cvss_score = None
                severity = None

                # Try CVSS v3.1
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore")
                    severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity")

                # fallback v3.0
                elif "cvssMetricV30" in metrics:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore")
                    severity = metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity")

                return {
                    "cve_id": cve_id,
                    "description": description_text,
                    "published": vuln.get("published"),
                    "last_modified": vuln.get("lastModified"),
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "source": "NVD"
                }

        except Exception:
            return None

    # ---------------------------------------------------------
    # ✅ Existing Working: CISA KEV Fetch
    # ---------------------------------------------------------
    async def fetch_cisa_kev(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Check if CVE is in CISA Known Exploited Vulnerabilities (KEV).
        """
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(self.cisa_kev_url)
                r.raise_for_status()
                data = r.json()

                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    if v.get("cveID", "").upper() == cve_id.upper():
                        return {
                            "cve_id": cve_id,
                            "known_exploited": True,
                            "vendor_project": v.get("vendorProject"),
                            "product": v.get("product"),
                            "vulnerability_name": v.get("vulnerabilityName"),
                            "date_added": v.get("dateAdded"),
                            "required_action": v.get("requiredAction"),
                            "due_date": v.get("dueDate"),
                            "source": "CISA_KEV"
                        }

                return {"cve_id": cve_id, "known_exploited": False, "source": "CISA_KEV"}

        except Exception:
            return None

    # ---------------------------------------------------------
    # ✅ NEW: AlienVault OTX Keyword Intel (APT / Malware / Ransomware)
    # ---------------------------------------------------------
    async def fetch_otx_pulses(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Fetch keyword-based threat intel from AlienVault OTX.
        Works for:
        - APT names (APT38, Lazarus Group)
        - Malware families (LockBit, Emotet)
        - Exploit keywords (Log4Shell)
        """
        q = (query or "").strip()
        if not q:
            return []

        params = {"q": q}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(self.otx_search_url, params=params)
                if r.status_code != 200:
                    return []

                data = r.json()
                results = data.get("results", [])

                pulses = []
                for p in results[:limit]:
                    pulses.append({
                        "name": p.get("name"),
                        "description": p.get("description"),
                        "author": p.get("author_name"),
                        "created": p.get("created"),
                        "modified": p.get("modified"),
                        "tags": p.get("tags", []),
                        "references": p.get("references", []),
                        "tlp": p.get("tlp"),
                        "adversary": p.get("adversary"),
                        "targeted_countries": p.get("targeted_countries", []),
                        "malware_families": p.get("malware_families", []),
                        "attack_ids": p.get("attack_ids", []),
                        "industries": p.get("industries", []),
                        "source": "OTX"
                    })

                return pulses

        except Exception:
            return []
