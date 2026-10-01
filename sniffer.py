from scapy.all import sniff, IP, TCP, UDP
import csv
from datetime import datetime

file = open("sniffer_log.csv", "w", newline="")
writer = csv.writer(file)

writer.writerow([
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Packet Size"
])

def show_packet(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:
            protocol = "Other"
            source_port = ""
            destination_port = ""

        packet_size = len(packet)

        print(
            f"{protocol} | "
            f"{source}:{source_port} -> "
            f"{destination}:{destination_port} | "
            f"Size: {packet_size} bytes"
        )

        writer.writerow([
            timestamp,
            source,
            destination,
            protocol,
            source_port,
            destination_port,
            packet_size
        ])

        file.flush()

print("Network Sniffer Started...")
print("Press Ctrl+C to stop.")

try:
    sniff(prn=show_packet, store=False)
except KeyboardInterrupt:
    print("\nSniffer stopped.")
finally:
    file.close()