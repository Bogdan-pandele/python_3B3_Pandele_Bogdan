import struct
import socket

class IPHeaders:
    def __init__(self, raw_data):
        ip_header_bytes = raw_data[:20]
        ip_header = struct.unpack("!BBHHHBBH4s4s", ip_header_bytes)

        self.version = ip_header[0] >> 4 #version
        # format(self.version, "08b")

        self.ihl = ip_header[0] & 0x0F  #header length
        # format(self.ihl, "08b")

        self.tos = ip_header[1] #type of service

        self.total_len = ip_header[2] #total length

        self.id = ip_header[3] #identification

        self.flags = ip_header[4] #flags
        # format(self.flags >> 13, "03b")

        self.offset = ip_header[4] & 0x1FFF #fragment offset
        
        self.ttl = ip_header[5] #time to live

        self.protocol = ip_header[6] #protocol used

        self.checksum = ip_header[7] #checksum

        self.src = socket.inet_ntoa(ip_header[8]) #source adress

        self.dest = socket.inet_ntoa(ip_header[9]) #destination adress

    def __str__(self):
            return (
                f"--- [IP Header] ---\n"
                f"Version: {self.version} | IHL: {self.ihl*4} bytes | ToS: {self.tos}\n"
                f"Total Length: {self.total_len} | ID: {self.id}\n"
                f"Flags: {self.flags} | Offset: {self.offset}\n"
                f"TTL: {self.ttl} | Protocol: {self.protocol} | Checksum: {self.checksum}\n"
                f"Source: {self.src} -> Destination: {self.dest}\n"
                f"-------------------"
            )

class TCP_Headers:
    def __init__(self, raw_data):
        tcp_header_bytes = raw_data[:20]
        tcp_header = struct.unpack("!HHLLBBHHH", tcp_header_bytes)

        self.src_port = tcp_header[0] #source port
        self.dest_port = tcp_header[1] #destination port
        self.seq = tcp_header[2] #sequence number
        self.ack = tcp_header[3] #acknowledgment number
        self.do = (tcp_header[4] >> 4) * 4 #data offset
        self.rsv = (tcp_header[4] >> 1) & 0x07 #reserved flags

        self.flags = tcp_header[5] #flags
        self.urg = (self.flags & 0x20) >> 5
        self.ack_f = (self.flags & 0x10) >> 4
        self.psh = (self.flags & 0x08) >> 3
        self.rst = (self.flags & 0x04) >> 2
        self.syn = (self.flags & 0x02) >> 1
        self.fin = (self.flags & 0x01)



        self.window = tcp_header[6] #window - how many bytes user recieves
        self.checksum = tcp_header[7] #checksum
        self.urgent_ptr = tcp_header[8] #urgent pointer
        
    def __str__(self):
        active_flags = []
        if self.urg: active_flags.append("URG")
        if self.ack_f: active_flags.append("ACK")  
        if self.psh: active_flags.append("PSH")
        if self.rst: active_flags.append("RST")
        if self.syn: active_flags.append("SYN")
        if self.fin: active_flags.append("FIN")
        
        flags_str = "|".join(active_flags) if active_flags else "None"

        return (
            f"[TCP Header] Port: {self.src_port} -> {self.dest_port}\n"
            f"Seq: {self.seq} | Ack: {self.ack}\n"
            f"Flags: [{flags_str}] | Window: {self.window} | DO: {self.do} bytes\n"
            f"-------------------"
        )
    

class HTTP_Request:
    def __init__(self, raw_data):
        self.method = ""
        self.path = ""
        self.version = ""
        self.host = ""
        self.user_agent = ""
        self.accept = ""
        self.content_type = ""
        self.content_length = 0
        self.date = ""
        
        try:
            parts = raw_data.decode(encoding="ascii").split("\r\n\r\n", 1)
            header = parts[0]
            self.body = parts[1] if len(parts) > 1 else ""
            lines = header.split("\r\n")
            first_line = lines[0].split()
            self.method = first_line[0]
            self.path = first_line[1]
            self.version = first_line[2]
            for line in lines:
                if line.startswith("Host: "):
                    self.host = line.replace("Host: ", "").strip()        
                elif line.startswith("User-Agent: "):
                    self.user_agent = line.replace("User-Agent: ", "").strip()
                elif line.startswith("Accept: "):
                    self.accept = line.replace("Accept: ", "").strip()
                elif line.startswith("Content-Type: "):
                    self.content_type = line.replace("Content-Type: ", "").strip()
                elif line.startswith("Content-Length: "):
                    self.content_length = (int)(line.replace("Content-Length: ", "").strip())
                elif line.lower().startswith("date: "):
                    self.date = line.split(": ", 1)[1].strip()
        except Exception as e:
            print(f"Error parsing HTTP request: {e}")

    def __str__(self):
        return (
            f"--- [HTTP REQUEST] ---\n"
            f"Method: {self.method}\n"
            f"Path:    {self.path}\n"
            f"UA:      {self.user_agent}\n"
            f"Date: {self.date}\n"
            f"Body: {len(self.body)} bytes\n"
            f"------------------------\n"
        )


class HTTP_Response:
    def __init__(self, raw_data):
        self.version = ""
        self.status_code = 0
        self.status_message = ""
        self.server = ""
        self.date = ""
        self.content_length = 0
        self.content_type = ""
        self.cache = ""
        try:
                parts = raw_data.decode(encoding="ascii").split("\r\n\r\n", 1)
                headers = parts[0]
                body = parts[1] if len(parts) > 1 else ""

                lines = headers.split("\r\n")
                first_line = lines[0].split()

                self.version = first_line[0]
                self.status_code = (int)(first_line[1])
                self.status_message = " ".join(first_line[2:])

                for line in lines:
                    if line.startswith("Server: "):
                        self.server = line.replace("Server: ", "").strip()
                    elif line.startswith("Date: "):
                        self.date = line.replace("Date: ", "").strip()
                    elif line.startswith("Content-Length: "):
                        self.content_length = (int)(line.replace("Content-Length: ", "").strip())
                    elif line.startswith("Content-Type: "):
                        self.content_type = line.replace("Content-Type: ", "").strip()
                    elif line.startswith("Cache-Control: "):
                        self.cache = line.replace("Cache-Control: ", "").strip()                    
        except Exception as e:
            print(f"Error parsing HTTP response: {e}")
    def __str__(self):
        return (
            f"--- [ HTTP RESPONSE ] ---\n"
            f"Status:  {self.status_code} {self.status_message}\n"
            f"Server:  {self.server}\n"
            f"Type:    {self.content_type}\n"
            f"Length:  {self.content_length} bytes\n"
            f"Date:    {self.date}\n"
            f"------------------------\n"
        )