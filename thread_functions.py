import queue
import socket
import threading
from headers import IPHeaders, TCP_Headers, HTTP_Request, HTTP_Response
from sys import platform


q: queue.Queue[bytes] = queue.Queue()
stop_signal = threading.Event()
http_verbs = ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"]


def capture_packets():
    """
    Initializes a raw socket and captures packets until signal is set(which happens at KeyboardInterrupt).
    Checks and handles sockets depending on OS:
    -Windows: Uses AF_INET and SIO_RCVALL for promiscuous mode to capture packets at Layer 3 (Network Layer)
    -Linux: Uses AF_PACKET to capture Ethernet Frames at Layer 2(Data Link Layer)

    Captures packets are placed in a Queue for later processing.
    """
    if platform == "win32":
        soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        HOST = get_my_ip()
        print(f"Sniffer  working on {HOST}")

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


def process_packets(methods=None, src=None, dest=None, filename="sniffer.txt"):
    """
    Parameters are the filtering arguments at the start of the program, filename represents the file in which the data is saved.

    Checks the global Queue for captured packets, then processes them. For TCP packets we check the protocol to be 6 (value of TCP),
    then it checks if it starts with a HTTP method(http_verbs for requests) or with HTTP/ (for Responses), otherwise it ignores the packet.

    Writes output to file. q.task_done() marks the task as done, so when the main process calls q.join() it doesn't wait forever.
    """
    with open(filename, "a", encoding="utf-8") as f:
        f.truncate(0)
        while True:
            raw_data = q.get()
            if platform != "win32":
                raw_data = raw_data[14:]
            try:
                ip_headers = IPHeaders(raw_data)

                if (ip_headers.src != src and src is not None) or (
                    ip_headers.dest != dest and dest is not None
                ):
                    continue

                if ip_headers.protocol == 6:
                    tcp_headers = TCP_Headers(raw_data[ip_headers.ihl * 4 :])
                    data = raw_data[ip_headers.ihl * 4 + tcp_headers.do :]
                    if any(
                        v in data[:10].decode("ascii", errors="ignore")
                        for v in http_verbs
                    ):
                        http_req = HTTP_Request(data)

                        if methods is not None:
                            if http_req.method not in methods:
                                continue

                        output = f"{ip_headers}\n{tcp_headers}\n{http_req}"
                        f.write(output + "\n" + "=" * 50 + "\n")
                        f.flush()
                        print(output + "\n\n")

                    elif "HTTP/" in data[:10].decode("ascii", errors="ignore"):
                        http_resp = HTTP_Response(data)
                        output = f"{ip_headers}\n{tcp_headers}\n{http_resp}"
                        f.write(output + "\n" + "=" * 50 + "\n")
                        f.flush()
                        print(output + "\n\n")

            except Exception as e:
                print(f"Error: {e}")
            finally:
                q.task_done()


def get_my_ip():
    """Returns the HOST IP for bind"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()

    return ip
