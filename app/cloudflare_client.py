"""
Cloudflare API Client - Fetch DNS A records from all zones
"""
import requests
from typing import List, Dict, Optional


CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"


def get_all_zones(api_token: str) -> List[Dict]:
    """
    Fetch all zones from Cloudflare account.
    
    Returns:
        List of zone dicts with 'id' and 'name'
    """
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    zones = []
    page = 1
    
    while True:
        url = f"{CLOUDFLARE_API_BASE}/zones"
        params = {"page": page, "per_page": 50}
        
        resp = requests.get(url, headers=headers, params=params)
        data = resp.json()
        
        if not data.get("success"):
            raise Exception(f"Cloudflare API error: {data.get('errors', 'Unknown error')}")
        
        zones.extend(data.get("result", []))
        
        # Check for more pages
        result_info = data.get("result_info", {})
        total_pages = result_info.get("total_pages", 1)
        
        if page >= total_pages:
            break
        page += 1
    
    return zones


def get_a_records(api_token: str, zone_id: str) -> List[Dict]:
    """
    Fetch all A records for a specific zone.
    
    Returns:
        List of dicts with 'name' (domain) and 'content' (IP)
    """
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    records = []
    page = 1
    
    while True:
        url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records"
        params = {"type": "A", "page": page, "per_page": 100}
        
        resp = requests.get(url, headers=headers, params=params)
        data = resp.json()
        
        if not data.get("success"):
            raise Exception(f"Cloudflare API error: {data.get('errors', 'Unknown error')}")
        
        records.extend(data.get("result", []))
        
        result_info = data.get("result_info", {})
        total_pages = result_info.get("total_pages", 1)
        
        if page >= total_pages:
            break
        page += 1
    
    return records


def fetch_all_a_records(api_token: str, progress_callback=None) -> List[Dict]:
    """
    Fetch all A records from all zones in the account.
    
    Args:
        api_token: Cloudflare API token
        progress_callback: Optional callback(message) for progress updates
    
    Returns:
        List of dicts with 'domain' and 'ip' keys
    """
    if progress_callback:
        progress_callback("Fetching zones from Cloudflare...")
    
    zones = get_all_zones(api_token)
    
    if progress_callback:
        progress_callback(f"Found {len(zones)} zones, fetching A records...")
    
    items = []
    
    for i, zone in enumerate(zones):
        zone_id = zone["id"]
        zone_name = zone["name"]
        
        if progress_callback:
            progress_callback(f"Fetching A records from {zone_name} ({i+1}/{len(zones)})")
        
        try:
            records = get_a_records(api_token, zone_id)
            for record in records:
                items.append({
                    "domain": record["name"],
                    "ip": record["content"]
                })
        except Exception as e:
            print(f"Error fetching records from {zone_name}: {e}")
    
    if progress_callback:
        progress_callback(f"Fetched {len(items)} A records from {len(zones)} zones")
    
    return items
