import socket
import threading
import time
from headers import IPHeaders, TCP_Headers
from thread_functions import process_packets, capture_packets, q, stop_signal
from sys import platform
import argparse

def main():



    if platform != "win32" and not platform.startswith("linux"):
        raise NotImplementedError(f"{platform} OS not supported")
    

    parser = argparse.ArgumentParser(prog="HTTP Sniffer")
    parser.add_argument("-m", "--method", type=str, choices=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"])
    parser.add_argument("--src", type=str)
    parser.add_argument("--dest", type=str)

    args = parser.parse_args()
    t1 = threading.Thread(target=capture_packets, daemon=True)
    t2 = threading.Thread(target=process_packets, args=(args.method, args.src, args.dest), daemon=True)


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