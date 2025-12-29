import queue
import socket
import threading
from headers import IPHeaders, TCP_Headers
from sys import platform


q: queue.Queue[bytes] = queue.Queue()
stop_signal = threading.Event()
http_verbs = ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "HTTP/"]


def capture_packets():
    if platform == "win32":
        soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        HOST = "192.168.1.155"

        soc.bind((HOST, 0))
        soc.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    elif platform == "linux" or platform == "linux2":
        soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    soc.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    soc.settimeout(1.0)

    while not stop_signal.is_set():
        try:
            raw_data, _ = soc.recvfrom(65565)
            q.put(raw_data)
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Error: {e}")


def process_packets():
    while True:
        raw_data = q.get()
        if platform != "win32":
            raw_data = raw_data[14:]
        try:
            ip_headers = IPHeaders(raw_data)

            if ip_headers.protocol == 6:  # TCP has value of 6
                tcp_headers = TCP_Headers(raw_data[ip_headers.ihl * 4 :])
                data = raw_data[ip_headers.ihl * 4 + tcp_headers.do:]
                if any(v in data[:10].decode('ascii', errors='ignore') for v in http_verbs):
                    print(ip_headers)
                    print(tcp_headers)
                    print(data.decode(encoding="ascii"))
                    print("\n\n")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            q.task_done()
