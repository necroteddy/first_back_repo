"""
Fast Port Scanner
-----------------
Checks which ports are open on a computer.
This version is FAST. It checks many ports at once.
 
RULE: Only scan your own computer.
Or scan with permission.
Scanning others can be illegal.
"""
 
import socket
from concurrent.futures import ThreadPoolExecutor
 
# The computer to scan.
# "127.0.0.1" means YOUR OWN computer.
TARGET = "127.0.0.1"
 
# Which ports to check.
START_PORT = 1
END_PORT = 1024
 
# How long to wait per port (in seconds).
TIMEOUT = 0.5
 
# How many ports to check at the same time.
# Higher = faster.
WORKERS = 200
 
 
def scan_port(port):
    """Check one port. Return the port number if open. Else None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
 
    # Result 0 means the port is OPEN.
    result = s.connect_ex((TARGET, port))
    s.close()
 
    if result == 0:
        return port
    return None
 
 
def main():
    print(f"Scanning {TARGET} ...")
    print(f"Ports {START_PORT} to {END_PORT}")
    print("Please wait.\n")
 
    ports = range(START_PORT, END_PORT + 1)
    open_ports = []
 
    # Run many checks at the same time.
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = pool.map(scan_port, ports)
 
    # Keep only the open ports.
    for port in results:
        if port is not None:
            print(f"Port {port} is OPEN")
            open_ports.append(port)
 
    # Show the result.
    print("\nDone.")
    if open_ports:
        print(f"Open ports: {sorted(open_ports)}")
    else:
        print("No open ports found.")
 
 
if __name__ == "__main__":
    main()