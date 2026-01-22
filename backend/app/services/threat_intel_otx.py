import httpx
from typing import Dict, Any, List


class OTXIntel:
    BASE_URL = "https://otx.alienvault.com/api/v1"

    async def search_pulses(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Search OTX pulses by keyword (APT name, malware family, etc.)
        """
        url = f"{self.BASE_URL}/search/pulses"
        params = {"q": query}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, params=params)
                if r.status_code != 200:
                    return []
                data = r.json()
        except Exception:
            return []

        results = []
        pulses = data.get("results", [])[:limit]

        for p in pulses:
            results.append({
                "name": p.get("name"),
                "description": p.get("description"),
                "author": p.get("author_name"),
                "created": p.get("created"),
                "modified": p.get("modified"),
                "tags": p.get("tags", []),
                "references": p.get("references", []),
            })

        return results
