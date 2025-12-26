import socket
import threading
from headers import IPHeaders, TCP_Headers
from thread_functions import process_packets, capture_packets

t1 = threading.Thread(target=capture_packets, daemon=True)
t2 = threading.Thread(target=process_packets, daemon=True)

t1.start()
t2.start()

try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stop")