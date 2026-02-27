# traffic_analyzer.py
# Analyze HTTPS encrypted traffic metadata

import pyshark
import matplotlib.pyplot as plt
from collections import defaultdict

# Load the captured pcap file
# Make sure the file is in same folder as this script
capture = pyshark.FileCapture('https_capture.pcapng')

packet_sizes = []                 # Store packet sizes
inter_arrival_times = []          # Store time difference between packets
ip_counter = defaultdict(int)     # Count packets by IP

previous_time = None

print("Reading packets... Please wait.")

for packet in capture:
    try:
        # Only process packets that have IP layer
        if 'IP' in packet:
            
            # Get packet size
            size = int(packet.length)
            packet_sizes.append(size)
            
            # Count packets by source and destination IP
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            ip_counter[src_ip] += 1
            ip_counter[dst_ip] += 1
            
            # Calculate inter-arrival time
            current_time = float(packet.sniff_timestamp)
            if previous_time is not None:
                inter_arrival_times.append(current_time - previous_time)
            previous_time = current_time

    except:
        # Ignore any packet parsing errors
        continue

capture.close()

print("\n--- Analysis Results ---")

# Print basic statistics
print(f"Total Packets Analyzed: {len(packet_sizes)}")
print(f"Average Packet Size: {sum(packet_sizes)/len(packet_sizes):.2f} bytes")

if inter_arrival_times:
    avg_time = sum(inter_arrival_times)/len(inter_arrival_times)
    print(f"Average Inter-arrival Time: {avg_time:.6f} seconds")

print("\nTop 5 Most Active IP Addresses:")
sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
for ip, count in sorted_ips[:5]:
    print(f"{ip} -> {count} packets")

# -----------------------------
# Packet Size Distribution Plot
# -----------------------------

# Create size ranges manually
bins = [0, 200, 400, 600, 800, 1000, 1500]
labels = ["0-200", "200-400", "400-600", "600-800", "800-1000", "1000-1500"]
distribution = [0] * (len(bins) - 1)

# Count packet sizes in each range
for size in packet_sizes:
    for i in range(len(bins)-1):
        if bins[i] <= size < bins[i+1]:
            distribution[i] += 1
            break

# Plot bar chart
plt.bar(labels, distribution)
plt.xlabel("Packet Size Range (Bytes)")
plt.ylabel("Number of Packets")
plt.title("HTTPS Packet Size Distribution")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
