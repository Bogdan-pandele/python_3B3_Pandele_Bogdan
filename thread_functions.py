import queue
import socket
from headers import IPHeaders, TCP_Headers
from sys import platform


q : queue.Queue[bytes] = queue.Queue()

def capture_packets():
    if(platform == "win32"):
        soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        HOST = "192.168.1.155"

        soc.bind((HOST, 0))
        soc.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    elif(platform == "linux" or platform == "linux2"):
        soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    soc.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)

    while True:
        try:
            raw_data, _ = soc.recvfrom(65565)
            q.put(raw_data)
        except Exception as e:
            print(f"Error: {e}")




def process_packets():
    while True:
        raw_data = q.get()

        try:
            ip_headers = IPHeaders(raw_data)

            if(ip_headers.protocol == 6): #TCP has value of 6
                tcp_headers = TCP_Headers(raw_data[ip_headers.ihl * 4:])
                print(ip_headers)
                print(tcp_headers)
                print("\n\n")
        except Exception as e:
            print(f"Error: {e}")

        q.task_done()