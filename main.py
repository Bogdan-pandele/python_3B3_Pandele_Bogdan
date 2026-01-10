import threading
import time
from thread_functions import process_packets, capture_packets, q, stop_signal
from sys import platform
import argparse
import json


def main():
    """
    Parses command-line arguments for filtering (methods, IP source/destination),
    saves the configuration to a JSON file and manages the processing and capturing
    of packets using threads.

    Shutdown on KeyboardInterrupt
    """

    if platform != "win32" and not platform.startswith("linux"):
        raise NotImplementedError(f"{platform} OS not supported")

    parser = argparse.ArgumentParser(prog="HTTP Sniffer")
    parser.add_argument(
        "-m",
        "--methods",
        type=str,
        nargs="+",
        choices=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"],
    )
    parser.add_argument("--src", type=str)
    parser.add_argument("--dest", type=str)

    args = parser.parse_args()

    config = {"methods": args.methods, "src": args.src, "dest": args.dest}

    with open("last_config.json", "w") as f:
        json.dump(config, f)

    if args.methods:
        print("Filtering methods: " + ", ".join(args.methods))
    else:
        print("No method filter")

    if args.src:
        print(f"Source IP: {args.src}")

    if args.dest:
        print(f"Destination IP: {args.dest}")

    t1 = threading.Thread(target=capture_packets, daemon=True)
    t2 = threading.Thread(
        target=process_packets, args=(args.methods, args.src, args.dest), daemon=True
    )

    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("Stop")
        stop_signal.set()

        q.join()


if __name__ == "__main__":
    main()
