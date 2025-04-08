from scapy.all import rdpcap, IP, TCP, UDP

# Step 1: Load the .pcapng file
pcap_file_path = r"C:\Users\Bakr'\OneDrive\Desktop\Sec\readings1.pcapng"
packets = rdpcap(pcap_file_path)

# Step 2: Analyze packet details
print("Analyzing packets...\n")
packet_details = []
for packet in packets:
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        port = (
            packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
        )
        packet_details.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "port": port
        })

# Display the first 10 packet details for inspection
for detail in packet_details[:10]:
    print(detail)

# Step 3: Define firewall rules based on the analysis
ALLOWED_IPS = ["192.168.1.1", "10.0.0.5","192.168.100.4"]
BLOCKED_PORTS = [22, 80]                  
# Step 4: Firewall function with debug logs
def firewall(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if the source IP is allowed
        if src_ip not in ALLOWED_IPS:
            print(f"Blocked: SRC IP {src_ip} not in allowed list")
            return f"Blocked: SRC IP {src_ip} not allowed"
        
        # Check if the port is blocked
        if TCP in packet or UDP in packet:
            port = (
                packet[TCP].dport if TCP in packet else packet[UDP].dport
            )
            if port and port in BLOCKED_PORTS:
                print(f"Blocked: Port {port} is restricted")
                return f"Blocked: Port {port} is restricted"
        
        print(f"Allowed: Packet from {src_ip} to {dst_ip}")
        return f"Allowed: Packet from {src_ip} to {dst_ip}"
    print("Blocked: Non-IP packet")
    return "Blocked: Non-IP packet"

# Step 5: Process packets and log results
print("\nProcessing packets through the firewall...\n")
results = [firewall(packet) for packet in packets]

# Step 6: Output results
blocked = [res for res in results if "Blocked" in res]
allowed = [res for res in results if "Allowed" in res]

print(f"Blocked packets: {len(blocked)}")
print(f"Allowed packets: {len(allowed)}")

# Save results to a file
output_file = "firewall_log.txt"
with open(output_file, "w") as log_file:
    log_file.write("\n".join(results))

print(f"Firewall log saved to {output_file}")