from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, IPvAnyAddress
import socket

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="."), name="static")

class ScanRequest(BaseModel):
    ip: IPvAnyAddress

def scan_port(ip: str, port: int) -> bool:
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(1)
    try:
        result = scanner.connect_ex((ip, port))
        scanner.close()
        return result == 0
    except socket.error:
        return False

@app.get("/")
async def read_root():
    return FileResponse("index.html")

@app.post("/scan")
async def scan(request: ScanRequest):
    ip = str(request.ip)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    results = {}
    
    for port in common_ports:
        results[port] = "OPEN" if scan_port(ip, port) else "CLOSED"
    
    return results