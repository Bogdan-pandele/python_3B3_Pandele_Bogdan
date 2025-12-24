import socket
from structs import IPHeaders, TCP_Headers

soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

HOST = "192.168.1.155"

soc.bind((HOST, 0))

soc.settimeout(5.0)

soc.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) #promiscuous mode


#TODO: verificare doar tcp +  asigurare ca nu sunt pierdute + testare linux 

while True:
    try:
        packet = soc.recvfrom(65565)
        packet_raw_data = packet[0]
        ip_headers = IPHeaders(packet_raw_data)
        tcp_headers = TCP_Headers(packet_raw_data)
        print(ip_headers)
        print(tcp_headers)
        print("\n\n")
    except socket.timeout:
        print("Waiting...")
        continue
    except KeyboardInterrupt:
        print("Stop")
        break
        
