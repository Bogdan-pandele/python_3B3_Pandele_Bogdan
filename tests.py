import json
import os
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor


def load_config():
    """Read the configuration saved at the start of the program(Filtering  methods, Source IP, Destination IP)"""
    with open("last_config.json", "r") as f:
        return json.load(f)


def send_curl(method, url):
    """Send a simple curl with the specified method to the specified url"""
    devnull = "nul" if os.name == "nt" else "/dev/null"
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", devnull, "-X", method, url], capture_output=False
        )
        return result.returncode == 0
    except Exception:
        return False


def run_stress_test(count=100, method="GET", url="http://httpforever.com"):
    """
    Verifies how the sniffer works with many requests at the same time.

    Uses ThreadPool so the requests are not sent one at a time (10x faster than a for loop)

    """
    start = time.time()

    with ThreadPoolExecutor(max_workers=10) as exec:
        results = list(exec.map(lambda _: send_curl(method, url), range(count)))

    cnt = results.count(True)

    duration = time.time() - start
    print(f"Successful requests: {cnt}")
    print(f"Time: {duration:.2f} seconds")


def verify_packets_test(packets, expected_methods, expected_src, expected_dest):
    """
    Check that the packets captured in our sniffer file have the methods and IP source/destination that are filtered at the start of the program.
    Otherwise we have an error
    """
    for i, p in enumerate(packets):
        for line in p.split("\n"):
            if "Method:" in line and expected_methods:
                method = line.split(":")[1].strip()
                assert method in expected_methods, (
                    f"Error at packet {i + 1}: Method {method} not allowed!"
                )
            if "Source:" in line and expected_src:
                src = line.split("->")[0].replace("Source:", "").strip()
                assert src == expected_src, (
                    f"Error at packet {i + 1}: Source IP {expected_src} != {src}"
                )
            if "Destination:" in line and expected_dest:
                dest = line.split("Destination:")[1].strip()
                assert expected_dest == dest, (
                    f"Error at packet {i + 1}: Destination IP {expected_dest} != {dest}"
                )

    print("Tests succesful")


def run_tests(test_count=100):
    """

    Runs the stress test then verifies the integrity of the packets with verify_packet_test

    Checks that the packets that are saved in the file are at least the number of packets
    we send with curl during the stress test so we ensure we have no packet loss

    """
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
                verify_packets_test(
                    packets,
                    config.get("methods"),
                    config.get("src"),
                    config.get("dest"),
                )
                assert len(packets) >= test_count, (
                    f"Packet loss! Sent: {test_count}, Recieved: {len(packets)}"
                )
            except AssertionError:
                print("Assertion failed!")
    else:
        print("File sniffer.txt not found!")


if __name__ == "__main__":
    run_tests(test_count=100)
