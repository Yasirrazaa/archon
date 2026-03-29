import requests
import time
import subprocess

print("Starting all agents manually...")
p1 = subprocess.Popen(["uv", "run", "python", "scenarios/security_arena/orchestrator.py", "--host", "127.0.0.1", "--port", "9010"])
p2 = subprocess.Popen(["uv", "run", "python", "-m", "scenarios.security_arena.agents.attacker.agent", "--host", "127.0.0.1", "--port", "9021", "--model", "llama-3.3-70b-versatile"])
p3 = subprocess.Popen(["uv", "run", "python", "-m", "scenarios.security_arena.agents.defender.agent", "--host", "127.0.0.1", "--port", "9020", "--model", "llama-3.3-70b-versatile"])
p4 = subprocess.Popen(["uv", "run", "python", "-m", "scenarios.security_arena.agents.normal_user.agent", "--host", "127.0.0.1", "--port", "9022", "--model", "llama-3.3-70b-versatile"])

time.sleep(5)

urls = [
    "http://127.0.0.1:9010/.well-known/agent-card.json",
    "http://127.0.0.1:9021/.well-known/agent-card.json",
    "http://127.0.0.1:9020/.well-known/agent-card.json",
    "http://127.0.0.1:9022/.well-known/agent-card.json"
]

for url in urls:
    try:
        r = requests.get(url)
        print(f"{url}: {r.status_code}")
    except Exception as e:
        print(f"{url}: Failed to connect")

p1.terminate()
p2.terminate()
p3.terminate()
p4.terminate()
