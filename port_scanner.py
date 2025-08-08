from fastapi import FastAPI, HTTPException  # bringing in fastapi stuff + errors
from fastapi.staticfiles import StaticFiles  # for serving static files
from fastapi.responses import FileResponse  # to send files back like html
from pydantic import BaseModel, IPvAnyAddress  # for data validation (ip type check)
import socket  # for actually checking ports

app = FastAPI()  # making the fastapi app

# mounting a static directory so we can serve html/css/js files
app.mount("/static", StaticFiles(directory="."), name="static")

# making a request model so ip input is validated automatically
class ScanRequest(BaseModel):
    ip: IPvAnyAddress  # pydantic will yell if it’s not a valid ip

# function that checks if a specific port is open on an ip
def scan_port(ip: str, port: int) -> bool:
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create a tcp socket
    scanner.settimeout(1)  # don’t wait forever, 1 second is enough
    try:
        result = scanner.connect_ex((ip, port))  # try to connect to the port
        scanner.close()  # close after trying
        return result == 0  # 0 means success aka port open
    except socket.error:  # if something goes wrong
        return False  # treat it as closed

# this route just serves the main html page
@app.get("/")
async def read_root():
    return FileResponse("index.html")  # send the html file

# this route handles the port scan requests
@app.post("/scan")
async def scan(request: ScanRequest):
    ip = str(request.ip)  # get ip as a string
    # list of common ports we want to check
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    results = {}  # to store scan results
    
    # loop through each port and check if it’s open or closed
    for port in common_ports:
        results[port] = "OPEN" if scan_port(ip, port) else "CLOSED"
    
    return results  # send results back as json
