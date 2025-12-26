import socket
import threading
import time
from headers import IPHeaders, TCP_Headers
from thread_functions import process_packets, capture_packets, q, stop_signal
from sys import platform


if platform != "win32" and not platform.startswith("linux"):
    raise NotImplementedError(f"{platform} OS not supported")


t1 = threading.Thread(target=capture_packets, daemon=True)
t2 = threading.Thread(target=process_packets, daemon=True)


t1.start()
t2.start()

try:
    while True:
        time.sleep(0.1)
except KeyboardInterrupt:
    print("Stop")
    stop_signal.set()

    q.join()
