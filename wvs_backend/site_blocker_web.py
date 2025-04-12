#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import requests
import signal
import argparse
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
    
    return api_process

def wait_for_api(max_attempts=30):
    """Wait for the API server to be ready"""
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
        time.sleep(1)
    
    print("[-] Failed to connect to API server")
    return False

def start_mitm_web(port=8080, web_port=8081):
    """Start the MITM web proxy with web interface"""
    print(f"[+] Starting MITM web proxy on port {port} with web interface on port {web_port}...")
    mitm_process = subprocess.Popen(
        ["python", "site_blocker_web.py", "--port", str(port), "--web-port", str(web_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Register cleanup function
    atexit.register(lambda: mitm_process.terminate() if mitm_process.poll() is None else None)
    
    return mitm_process

def main():
    parser = argparse.ArgumentParser(description="Start the Web Vulnerability Scanner with web interface")
    parser.add_argument("--port", type=int, default=8080, help="Port for MITM proxy (default: 8080)")
    parser.add_argument("--web-port", type=int, default=8081, help="Port for MITM web interface (default: 8081)")
    parser.add_argument("--no-mitm", action="store_true", help="Don't start the MITM proxy")
    args = parser.parse_args()
    
    # Start the API server
    api_process = start_api_server()
    
    # Wait for API to be ready
    if not wait_for_api():
        print("[-] Failed to start API server. Check logs for details.")
        api_process.terminate()
        sys.exit(1)
    
    # Start MITM web interface if not disabled
    mitm_process = None
    if not args.no_mitm:
        mitm_process = start_mitm_web(args.port, args.web_port)
        print(f"[+] MITM web proxy started on port {args.port}")
        print(f"[+] MITM web interface available at http://localhost:{args.web_port}")
        print(f"[+] Configure your browser to use localhost:{args.port} as proxy")
    
    print("\n[+] Web Vulnerability Scanner is running")
    print("[+] API server: http://localhost:5000")
    print("[+] Press Ctrl+C to stop\n")
    
    # Stream API server output for debugging
    while True:
        try:
            api_line = api_process.stdout.readline()
            if api_line:
                print(f"[API] {api_line.decode().strip()}")
            
            if mitm_process:
                mitm_line = mitm_process.stdout.readline()
                if mitm_line:
                    print(f"[MITM] {mitm_line.decode().strip()}")
            
            # Check if processes are still running
            if api_process.poll() is not None:
                print("[-] API server stopped unexpectedly")
                break
                
            if mitm_process and mitm_process.poll() is not None:
                print("[-] MITM proxy stopped unexpectedly")
                
                # Output any error information
                stderr = mitm_process.stderr.read().decode()
                if stderr:
                    print(f"[-] MITM Error: {stderr}")
                    
                break
                
            time.sleep(0.1)
            
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            break
            
    # Clean up processes
    if api_process.poll() is None:
        api_process.terminate()
    
    if mitm_process and mitm_process.poll() is None:
        mitm_process.terminate()
    
    print("[+] All services stopped")

if __name__ == "__main__":
    main()