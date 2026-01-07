"""
Nmap Scanner Module - Parallel port scanning using python-nmap
"""
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.config import NMAP_WORKERS

# Ports to scan
SCAN_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,81,82,8081"


def scan_ip(ip: str) -> dict:
    """
    Scan a single IP address for open ports.
    
    Returns:
        dict with 'ip', 'ports' (string), and 'error' if any
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments=f'-Pn -sV -p {SCAN_PORTS}')
        
        port_descriptions = []
        
        if ip in nm.all_hosts():
            tcp_ports = nm[ip].get('tcp', {})
            for port, info in tcp_ports.items():
                if info.get('state') == 'open':
                    name = info.get('name', '')
                    product = info.get('product', '')
                    version = info.get('version', '')
                    desc = f"{port} - {name} {product} {version}".strip()
                    port_descriptions.append(desc)
        
        ports_str = ", ".join(port_descriptions) if port_descriptions else "null"
        
        return {
            "ip": ip,
            "ports": ports_str,
            "error": None
        }
    except Exception as e:
        return {
            "ip": ip,
            "ports": "scan_error",
            "error": str(e)
        }


def scan_batch(ips: list, progress_callback=None) -> list:
    """
    Scan multiple IPs in parallel using ThreadPoolExecutor.
    
    Args:
        ips: List of IP addresses to scan
        progress_callback: Optional callback(completed, total) for progress updates
    
    Returns:
        List of scan results
    """
    results = []
    total = len(ips)
    completed = 0
    
    with ThreadPoolExecutor(max_workers=NMAP_WORKERS) as executor:
        future_to_ip = {executor.submit(scan_ip, ip): ip for ip in ips}
        
        for future in as_completed(future_to_ip):
            result = future.result()
            results.append(result)
            completed += 1
            
            if progress_callback:
                progress_callback(completed, total, "nmap")
            
            print(f"[Nmap] Scanned {result['ip']}: {result['ports'][:50]}...")
    
    return results
