"""
Excel File Handler - Read uploads and write results
"""
import openpyxl
from openpyxl import Workbook
from typing import List, Dict
import os
from app.config import RESULTS_DIR


def read_excel(file_path: str) -> List[Dict]:
    """
    Read Excel file and extract domain/IP pairs.
    
    Expected format:
    - Column A: Domain
    - Column B: IP Address
    
    Returns:
        List of dicts with 'domain' and 'ip' keys
    """
    wb = openpyxl.load_workbook(file_path)
    ws = wb.active
    
    items = []
    for row in ws.iter_rows(min_row=1, values_only=True):
        domain = row[0] if len(row) > 0 else None
        ip = row[1] if len(row) > 1 else None
        
        if domain and ip:
            items.append({
                "domain": str(domain).strip(),
                "ip": str(ip).strip()
            })
    
    wb.close()
    return items


def write_excel(results: List[Dict], output_path: str) -> str:
    """
    Write scan results to Excel file.
    
    Output format:
    - Column A: Domain
    - Column B: IP
    - Column C: Ports
    - Column D: HTTP Status
    - Column E: HTTPS Status
    
    Returns:
        Path to created file
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Scan Results"
    
    # Headers
    headers = ["Domain", "IP", "Ports", "HTTP Status", "HTTPS Status"]
    for col, header in enumerate(headers, 1):
        ws.cell(row=1, column=col, value=header)
    
    # Data rows
    for row_idx, item in enumerate(results, 2):
        ws.cell(row=row_idx, column=1, value=item.get("domain", ""))
        ws.cell(row=row_idx, column=2, value=item.get("ip", ""))
        ws.cell(row=row_idx, column=3, value=item.get("ports", ""))
        ws.cell(row=row_idx, column=4, value=item.get("http_status", ""))
        ws.cell(row=row_idx, column=5, value=item.get("https_status", ""))
    
    # Auto-adjust column widths
    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width
    
    wb.save(output_path)
    wb.close()
    
    return output_path


def get_unique_ips(items: List[Dict]) -> List[str]:
    """
    Extract unique IP addresses from items list.
    """
    seen = set()
    unique = []
    for item in items:
        ip = item.get("ip")
        if ip and ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique
