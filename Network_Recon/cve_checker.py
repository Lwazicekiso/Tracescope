# cve_checker.py

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cves(service: str, version: str, max_results: int = 5):
    """
    Query the NVD API for CVEs matching service/version.
    Returns a list of dicts: [{id, description, publishedDate}, ...]
    """
    if version == "Unknown":
        return []

    query = f"{service} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": max_results
    }
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            c = item.get("cve", {})
            cves.append({
                "id": c.get("id"),
                "description": c.get("descriptions", [{}])[0].get("value"),
                "publishedDate": c.get("published")
            })
        return cves
    except Exception:
        return []
