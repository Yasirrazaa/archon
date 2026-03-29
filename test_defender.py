import subprocess
import time
import requests
import sys

print("Starting defender...")
proc = subprocess.Popen(["uv", "run", "python", "-m", "scenarios.security_arena.agents.defender.agent", "--port", "9020", "--model", "llama-3.3-70b-versatile"])
time.sleep(3)

print("Checking if defender is up...")
try:
    resp = requests.get("http://127.0.0.1:9020/")
    print(f"Status: {resp.status_code}")
except Exception as e:
    print(f"Failed to connect: {e}")
    
proc.terminate()
