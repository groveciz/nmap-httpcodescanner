"""
FastAPI Main Application
"""
from fastapi import FastAPI, UploadFile, File, Request, BackgroundTasks, Form
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uuid
import os
import shutil
from typing import Dict, Optional

from app.config import UPLOADS_DIR, RESULTS_DIR
from app.scanner import scan_batch
from app.http_checker import check_batch
from app.excel_handler import read_excel, write_excel, get_unique_ips, write_cloudflare_excel
from app.cloudflare_client import fetch_all_a_records

app = FastAPI(
    title="Nmap HTTP Code Scanner",
    description="Network scanner with parallel Nmap and HTTP status checking",
    version="1.0.0"
)

# Templates
templates = Jinja2Templates(directory="templates")

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory job storage
jobs: Dict[str, dict] = {}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main page with upload form."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/upload")
async def upload_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Handle Excel file upload and start scan job.
    """
    # Generate job ID
    job_id = str(uuid.uuid4())[:8]
    
    # Save uploaded file
    upload_path = os.path.join(UPLOADS_DIR, f"{job_id}.xlsx")
    with open(upload_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Initialize job status
    jobs[job_id] = {
        "status": "processing",
        "phase": "reading",
        "progress": 0,
        "total": 0,
        "message": "Reading Excel file...",
        "result_file": None
    }
    
    # Start background scan
    background_tasks.add_task(run_scan, job_id, upload_path)
    
    # Return HTMX partial with job ID
    return templates.TemplateResponse(
        "partials/progress.html",
        {"request": request, "job_id": job_id, "job": jobs[job_id]}
    )


def update_progress(completed: int, total: int, phase: str, job_id: str):
    """Callback to update job progress."""
    if job_id in jobs:
        jobs[job_id]["progress"] = completed
        jobs[job_id]["total"] = total
        jobs[job_id]["phase"] = phase
        
        if phase == "nmap":
            jobs[job_id]["message"] = f"Scanning ports: {completed}/{total}"
        elif phase == "http":
            jobs[job_id]["message"] = f"Checking HTTP: {completed}/{total}"


def run_scan(job_id: str, upload_path: str):
    """
    Background task to run the full scan pipeline.
    """
    try:
        # Phase 1: Read Excel
        jobs[job_id]["message"] = "Reading Excel file..."
        items = read_excel(upload_path)
        
        if not items:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["message"] = "No valid data found in Excel"
            return
        
        # Phase 2: Get unique IPs and scan
        unique_ips = get_unique_ips(items)
        jobs[job_id]["total"] = len(unique_ips)
        jobs[job_id]["phase"] = "nmap"
        jobs[job_id]["message"] = f"Starting Nmap scan for {len(unique_ips)} IPs..."
        
        # Create progress callback
        def nmap_progress(completed, total, phase):
            update_progress(completed, total, phase, job_id)
        
        scan_results = scan_batch(unique_ips, progress_callback=nmap_progress)
        
        # Build IP -> ports mapping
        ip_to_ports = {r["ip"]: r["ports"] for r in scan_results}
        
        # Add ports to items
        for item in items:
            item["ports"] = ip_to_ports.get(item["ip"], "null")
        
        # Phase 3: HTTP check
        jobs[job_id]["total"] = len(items)
        jobs[job_id]["phase"] = "http"
        jobs[job_id]["message"] = f"Checking HTTP status for {len(items)} domains..."
        
        def http_progress(completed, total, phase):
            update_progress(completed, total, phase, job_id)
        
        http_results = check_batch(items, progress_callback=http_progress)
        
        # Merge HTTP results into items
        domain_to_http = {r["domain"]: r for r in http_results}
        for item in items:
            http_data = domain_to_http.get(item["domain"], {})
            http_status = http_data.get("http_status", "")
            https_status = http_data.get("https_status", "")
            http_default = http_data.get("http_default", "")
            https_default = http_data.get("https_default", "")
            
            # Replace status with "default page" if default page detected
            if http_default == "True":
                http_status = "default page"
            if https_default == "True":
                https_status = "default page"
            
            # Apply http-only / https-only labels
            if http_status and not https_status:
                https_status = "http-only"
            elif https_status and not http_status:
                http_status = "https-only"
            
            item["http_status"] = http_status
            item["https_status"] = https_status
        
        # Phase 4: Write results
        jobs[job_id]["message"] = "Writing results..."
        result_path = os.path.join(RESULTS_DIR, f"{job_id}_results.xlsx")
        write_cloudflare_excel(items, result_path)
        
        # Mark complete
        jobs[job_id]["status"] = "complete"
        jobs[job_id]["message"] = f"Scan complete! {len(items)} domains processed."
        jobs[job_id]["result_file"] = f"{job_id}_results.xlsx"
        
        # Cleanup upload
        if os.path.exists(upload_path):
            os.remove(upload_path)
            
    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["message"] = f"Error: {str(e)}"


@app.get("/status/{job_id}")
async def get_status(request: Request, job_id: str):
    """
    Get job status (used by HTMX polling).
    """
    job = jobs.get(job_id, {"status": "not_found", "message": "Job not found"})
    return templates.TemplateResponse(
        "partials/progress.html",
        {"request": request, "job_id": job_id, "job": job}
    )


@app.get("/download/{filename}")
async def download_file(filename: str):
    """
    Download result Excel file.
    """
    file_path = os.path.join(RESULTS_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    return JSONResponse({"error": "File not found"}, status_code=404)


@app.post("/cloudflare")
async def cloudflare_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    api_token: str = Form(...)
):
    """
    Start scan using Cloudflare API to fetch A records.
    """
    # Generate job ID
    job_id = str(uuid.uuid4())[:8]
    
    # Initialize job status
    jobs[job_id] = {
        "status": "processing",
        "phase": "cloudflare",
        "progress": 0,
        "total": 0,
        "message": "Connecting to Cloudflare...",
        "result_file": None
    }
    
    # Start background scan
    background_tasks.add_task(run_cloudflare_scan, job_id, api_token)
    
    # Return HTMX partial with job ID
    return templates.TemplateResponse(
        "partials/progress.html",
        {"request": request, "job_id": job_id, "job": jobs[job_id]}
    )


@app.post("/cloudflare-test")
async def cloudflare_test_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    api_token: str = Form(...)
):
    """
    Test scan - only first 10 A records from Cloudflare.
    """
    job_id = str(uuid.uuid4())[:8]
    
    jobs[job_id] = {
        "status": "processing",
        "phase": "cloudflare",
        "progress": 0,
        "total": 0,
        "message": "Connecting to Cloudflare (TEST MODE - 10 records)...",
        "result_file": None
    }
    
    background_tasks.add_task(run_cloudflare_scan, job_id, api_token, limit=10)
    
    return templates.TemplateResponse(
        "partials/progress.html",
        {"request": request, "job_id": job_id, "job": jobs[job_id]}
    )


def run_cloudflare_scan(job_id: str, api_token: str, limit: int = None):
    """
    Background task to fetch Cloudflare A records and run scan.
    
    Args:
        limit: Optional limit on number of records to scan (for testing)
    """
    try:
        # Phase 1: Fetch from Cloudflare
        def cf_progress(message):
            jobs[job_id]["message"] = message
        
        jobs[job_id]["phase"] = "cloudflare"
        items = fetch_all_a_records(api_token, progress_callback=cf_progress)
        
        # Apply limit if specified (test mode)
        if limit and len(items) > limit:
            items = items[:limit]
            jobs[job_id]["message"] = f"TEST MODE: Using first {limit} of {len(items)} records"
        
        if not items:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["message"] = "No A records found in Cloudflare"
            return
        
        jobs[job_id]["message"] = f"Found {len(items)} A records, starting scan..."
        
        # Phase 2: Get unique IPs and scan
        unique_ips = get_unique_ips(items)
        jobs[job_id]["total"] = len(unique_ips)
        jobs[job_id]["phase"] = "nmap"
        jobs[job_id]["message"] = f"Starting Nmap scan for {len(unique_ips)} IPs..."
        
        def nmap_progress(completed, total, phase):
            update_progress(completed, total, phase, job_id)
        
        scan_results = scan_batch(unique_ips, progress_callback=nmap_progress)
        
        # Build IP -> ports mapping
        ip_to_ports = {r["ip"]: r["ports"] for r in scan_results}
        
        # Add ports to items
        for item in items:
            item["ports"] = ip_to_ports.get(item["ip"], "null")
        
        # Phase 3: HTTP check
        jobs[job_id]["total"] = len(items)
        jobs[job_id]["phase"] = "http"
        jobs[job_id]["message"] = f"Checking HTTP status for {len(items)} domains..."
        
        def http_progress(completed, total, phase):
            update_progress(completed, total, phase, job_id)
        
        http_results = check_batch(items, progress_callback=http_progress)
        
        # Merge HTTP results into items
        domain_to_http = {r["domain"]: r for r in http_results}
        for item in items:
            http_data = domain_to_http.get(item["domain"], {})
            http_status = http_data.get("http_status", "")
            https_status = http_data.get("https_status", "")
            http_default = http_data.get("http_default", "")
            https_default = http_data.get("https_default", "")
            
            # Replace status with "default page" if default page detected
            if http_default == "True":
                http_status = "default page"
            if https_default == "True":
                https_status = "default page"
            
            # Apply http-only / https-only labels
            if http_status and not https_status:
                https_status = "http-only"
            elif https_status and not http_status:
                http_status = "https-only"
            
            item["http_status"] = http_status
            item["https_status"] = https_status
        
        # Phase 4: Write results
        jobs[job_id]["message"] = "Writing results..."
        result_path = os.path.join(RESULTS_DIR, f"{job_id}_cloudflare_results.xlsx")
        write_cloudflare_excel(items, result_path)
        
        # Mark complete
        jobs[job_id]["status"] = "complete"
        jobs[job_id]["message"] = f"Scan complete! {len(items)} domains from Cloudflare processed."
        jobs[job_id]["result_file"] = f"{job_id}_cloudflare_results.xlsx"
        
    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["message"] = f"Error: {str(e)}"


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

