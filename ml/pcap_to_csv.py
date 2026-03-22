import sys
import csv
import os
from scapy.all import rdpcap, IP, TCP, UDP

if len(sys.argv) < 2:
    print("Usage: python pcap_to_csv.py <pcap_file>")
    sys.exit(1)

input_file = sys.argv[1]

try:
    packets = rdpcap(input_file)
except FileNotFoundError:
    print(f"File not found: {input_file}")
    sys.exit(1)
except Exception as e:
    print(f"Error reading pcap: {e}")
    sys.exit(1)

# Save CSV in uploads folder
uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(uploads_dir, exist_ok=True)

# Extract base name without extensions
base_name = os.path.basename(input_file)
for ext in [".pcapng", ".pcap", ".csv"]:
    if base_name.lower().endswith(ext):
        base_name = base_name[: -len(ext)]

csv_file = os.path.join(uploads_dir, base_name + ".csv")

with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["time", "src_ip", "dst_ip", "protocol", "length"])
    for pkt in packets:
        try:
            time = pkt.time
            src_ip = pkt[IP].src if IP in pkt else "unknown"
            dst_ip = pkt[IP].dst if IP in pkt else "unknown"
            protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else pkt.lastlayer().name
            length = len(pkt)
            writer.writerow([time, src_ip, dst_ip, protocol, length])
        except Exception:
            continue

print(f"CSV file saved as: {csv_file}")