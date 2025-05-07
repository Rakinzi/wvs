# run_celery.py
import subprocess
import sys
import time
import signal
import os

def start_celery():
    """Start Celery worker and beat scheduler"""
    print("Starting Celery Worker and Beat for SSL/TLS Checker...")
    
    # Start Celery worker process
    worker_process = subprocess.Popen(
        ['celery', '-A', 'app.celery_app', 'worker', '--loglevel=info'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    
    # Start Celery beat scheduler process
    beat_process = subprocess.Popen(
        ['celery', '-A', 'app.celery_app', 'beat', '--loglevel=info'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    
    print(f"Celery worker started (PID: {worker_process.pid})")
    print(f"Celery beat scheduler started (PID: {beat_process.pid})")
    print("SSL/TLS checker will run every 24 hours")
    print("\nPress Ctrl+C to stop all processes\n")
    
    # Handle process output
    try:
        while True:
            # Print output from worker
            worker_output = worker_process.stdout.readline()
            if worker_output:
                print(f"[WORKER] {worker_output.strip()}")
            
            # Print output from beat
            beat_output = beat_process.stdout.readline()
            if beat_output:
                print(f"[BEAT] {beat_output.strip()}")
            
            # Check if processes are still running
            if worker_process.poll() is not None and beat_process.poll() is not None:
                print("Both processes have terminated.")
                break
                
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nShutting down Celery processes...")
        
        # Terminate processes gracefully
        worker_process.terminate()
        beat_process.terminate()
        
        # Wait for processes to terminate
        worker_process.wait(timeout=5)
        beat_process.wait(timeout=5)
        
        print("Celery processes terminated.")

if __name__ == "__main__":
    start_celery()