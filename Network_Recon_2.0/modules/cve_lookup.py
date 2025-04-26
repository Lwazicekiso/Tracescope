# modules/cve_lookup.py

import requests
import os

def get_cves(service, version=None, api_key=None):
    """
    Query the NVD API for the most relevant CVEs for the given service and version.
    Returns up to 5 CVEs with id, description, and cvss_score.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query = service or ""
    if version:
        query = f"{query} {version}"
    params = {"keywordSearch": query, "resultsPerPage": 20}
    headers = {}
    key = api_key or os.getenv("NVD_API_KEY")
    if key:
        headers["apiKey"] = key

    print(f"[+] Querying NVD for CVEs matching: '{query}'")
    try:
        resp = requests.get(base_url, headers=headers, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[-] NVD API error: {e}")
        return []

    vulns = data.get("vulnerabilities", [])
    items = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        # pick English description
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang")=="en"), "")
        # pick highest CVSS score available
        metrics = cve.get("metrics", {})
        score = 0.0
        if v3 := metrics.get("cvssMetricV3"):
            score = v3[0].get("cvssData", {}).get("baseScore", 0.0)
        elif v2 := metrics.get("cvssMetricV2"):
            score = v2[0].get("cvssData", {}).get("baseScore", 0.0)
        items.append({"id": cve_id, "description": desc, "cvss_score": score})

    # sort and return top 5
    items.sort(key=lambda x: x["cvss_score"], reverse=True)
    top5 = items[:5]
    print(f"[+] Retrieved {len(top5)} CVEs")
    return top5
