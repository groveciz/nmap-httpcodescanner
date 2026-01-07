# Nmap HTTP Code Scanner

A lightweight, modern network scanner with parallel Nmap port scanning and HTTP/HTTPS status checking.

![Screenshot](https://via.placeholder.com/800x400/667eea/ffffff?text=Nmap+HTTP+Scanner)

## Features

- 🚀 **Parallel Scanning** - ThreadPoolExecutor for fast multi-IP scanning
- 🌐 **HTTP/HTTPS Analysis** - Status codes, SSL certificate validation
- 🔍 **Default Page Detection** - Pattern-based detection of placeholder pages
- 📊 **Excel Integration** - Upload Excel, get enriched results
- ⚡ **Real-time Progress** - HTMX-powered live updates
- 🎨 **Modern UI** - Tailwind CSS with gradient design

## Tech Stack

- **Backend:** FastAPI + Python
- **Frontend:** HTMX + Tailwind CSS
- **Scanning:** python-nmap
- **Excel:** openpyxl

## Installation

```bash
# Clone
git clone https://github.com/groveciz/nmap-httpcodescanner.git
cd nmap-httpcodescanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run
uvicorn app.main:app --reload
```

Open http://localhost:8000 in your browser.

## Input Format

Excel file with two columns:

| Column A | Column B |
|----------|----------|
| Domain   | IP Address |

## Output

- Ports (e.g., "80 - http Apache, 443 - https")
- HTTP Status
- HTTPS Status
- Default Page Detection

## Configuration

Edit `app/config.py`:

```python
NMAP_WORKERS = 10   # Parallel port scans
HTTP_WORKERS = 20   # Parallel HTTP requests
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main page |
| POST | `/upload` | Upload Excel |
| GET | `/status/{job_id}` | Scan progress |
| GET | `/download/{filename}` | Download results |

## Requirements

- Python 3.8+
- Nmap installed on system

## License

MIT
