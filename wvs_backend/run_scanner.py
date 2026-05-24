#!/usr/bin/env python3
import os
import sys
import argparse
import subprocess
import time
import requests
import atexit

def start_api_server():
    """Start the Flask API server"""
    print("[+] Starting Flask API server...")
    api_process = subprocess.Popen(
        ["python", "wsgi.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Register cleanup function
    atexit.register(lambda: api_process.terminate() if api_process.poll() is None else None)
    
    # Wait for API to start
    time.sleep(2)
    
    return api_process

def start_mitm_proxy(port=8080):
    """Start the MITM proxy for blocking malicious sites"""
    print(f"[+] Starting MITM proxy on port {port}...")
    mitm_process = subprocess.Popen(
        ["python", "site_blocker.py", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Register cleanup function
    atexit.register(lambda: mitm_process.terminate() if mitm_process.poll() is None else None)
    
    return mitm_process

def wait_for_api():
    """Wait for the API server to be ready"""
    max_attempts = 10
    attempts = 0
    
    while attempts < max_attempts:
        try:
            response = requests.get("http://localhost:5000/health")
            if response.status_code == 200:
                print("[+] API server is ready")
                return True
        except requests.exceptions.ConnectionError:
            pass
        
        print(f"[*] Waiting for API server to start ({attempts+1}/{max_attempts})...")
        attempts += 1
        time.sleep(2)
    
    print("[-] Failed to connect to API server")
    return False

def main():
    parser = argparse.ArgumentParser(description="Start the Web Vulnerability Scanner")
    parser.add_argument("--port", type=int, default=8080, help="Port for MITM proxy (default: 8080)")
    parser.add_argument("--no-mitm", action="store_true", help="Don't start the MITM proxy")
    args = parser.parse_args()
    
    # First, make sure the default application database exists.
    if not os.path.exists("instance/wvs.db") and not os.environ.get('DATABASE_URL'):
        print("[*] Local database not found, initializing default app schema...")
        subprocess.run(["python", "-m", "flask", "--app", "manage.py", "init-db"], check=False)
    
    # Start the API server
    api_process = start_api_server()
    
    # Wait for API to be ready
    if not wait_for_api():
        print("[-] Failed to start API server. Check logs for details.")
        sys.exit(1)
    
    # Start MITM proxy if not disabled
    mitm_process = None
    if not args.no_mitm:
        mitm_process = start_mitm_proxy(args.port)
        print(f"[+] MITM proxy started on port {args.port}")
        print(f"[+] Configure your browser to use localhost:{args.port} as proxy")
    
    print("\n[+] Web Vulnerability Scanner is running")
    print("[+] API server: http://localhost:5000")
    print("[+] Press Ctrl+C to stop\n")
    
    try:
        # Keep the main process running
        while True:
            time.sleep(1)
            
            # Check if processes are still running
            if api_process.poll() is not None:
                print("[-] API server stopped unexpectedly")
                break
                
            if mitm_process and mitm_process.poll() is not None:
                print("[-] MITM proxy stopped unexpectedly")
                break
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        # Clean up processes
        if api_process.poll() is None:
            api_process.terminate()
        
        if mitm_process and mitm_process.poll() is None:
            mitm_process.terminate()
        
        print("[+] All services stopped")

if __name__ == "__main__":
    main()
