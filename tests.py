import json
import os
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor

def load_config():
    with open("last_config.json", "r") as f:
        return json.load(f)


def send_curl(method, url):
    devnull = "nul" if os.name == "nt" else "/dev/null"
    try:
        result = subprocess.run(["curl", "-s", "-o", devnull, "-X", method, url], capture_output=False)
        return result.returncode == 0
    except Exception:
        return False


def run_stress_test(count = 100, method = "GET", url = "http://httpforever.com"):
    start = time.time()

    with ThreadPoolExecutor(max_workers=10) as exec:
        results = list(exec.map(lambda _: send_curl(method, url), range(count)))
    
    cnt = results.count(True)
    
    duration = time.time() - start
    print(f"Successful requests: {cnt}")
    print(f"Time: {duration:.2f} seconds")                

        


def verify_packets_test(packets, expected_methods, expected_src, expected_dest):
    
    for i, p in enumerate(packets):
        for line in p.split("\n"):
            if  "Method:" in line and expected_methods:
                method = line.split(":")[1].strip()
                assert method in expected_methods, f"Error at packet {i + 1}: Method {method} not allowed!"
            if  "Source:" in line and expected_src:
                src = line.split("->")[0].replace("Source:", "").strip()
                assert src == expected_src, f"Error at packet {i + 1}: Source IP {expected_src} != {src}"
            if "Destination:" in line and expected_dest:
                dest = line.split("Destination:")[1].strip()
                assert expected_dest  == dest, f"Error at packet {i + 1}: Destination IP {expected_dest} != {dest}"

    print("Tests succesful")



def run_tests(test_count = 100):
    try:
        config = load_config()
    except Exception:
        print("No configuration!")
        return
    
    test_method = config.get("methods")[0] if config.get("methods") else "GET"
    run_stress_test(count=test_count, method=test_method)

    time.sleep(2)

    if os.path.exists("sniffer.txt"):
        with open("sniffer.txt", "r", encoding="utf-8") as f:
            content = f.read().strip()
            packets = [p.strip() for p in content.split("=" * 50) if p.strip()]

            try:
                verify_packets_test(packets, config.get("methods"), config.get("src"), config.get("dest"))
                assert len(packets) >= test_count, f"Packet loss! Sent: {test_count}, Recieved: {len(packets)}"
            except AssertionError as e:
                print("Assertion failed!")
    else:
        print("File sniffer.txt not found!")

if __name__ == "__main__":
    run_tests(test_count=100)

