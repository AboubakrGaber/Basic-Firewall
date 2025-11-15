from scapy.all import sniff, IP, TCP, UDP
import datetime

log_file_path = "firewall_log.txt"

def log_message(message, log_type="INFO"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{log_type}] {timestamp} - {message}"
    print(log_entry)
    with open(log_file_path, "a") as log_file:
        log_file.write(log_entry + "\n")

ALLOWED_IPS = ["192.168.1.1", "10.0.0.5", "192.168.100.4","192.168.100.200"]
BLOCKED_IPS = ["192.168.1.100", "172.16.0.10"]
BLOCKED_PORTS = [22, 80]
ALLOWED_PORTS = [8080, 1234, 443]
ALERT_THRESHOLD = 5

block_counter = 0

def firewall(packet):
    global block_counter
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        port = (
            packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
        )

        # Check if the source IP is explicitly blocked
        if src_ip in BLOCKED_IPS:
            block_counter += 1
            log_message(f"Blocked: Malicious SRC IP {src_ip}", "WARNING")
            return f"Blocked: Malicious SRC IP {src_ip}"

        # Check if the source IP is allowed
        if src_ip not in ALLOWED_IPS:
            log_message(f"Blocked: SRC IP {src_ip} not in allowed list", "WARNING")
            block_counter += 1
            return f"Blocked: SRC IP {src_ip} not allowed"

        # Check if the port is blocked
        if port and port in BLOCKED_PORTS:
            log_message(f"Blocked: Port {port} is restricted", "WARNING")
            block_counter += 1
            return f"Blocked: Port {port} is restricted"

        # Explicitly allow specific ports
        if port and port not in ALLOWED_PORTS:
            log_message(f"Blocked: Port {port} not in allowed list", "WARNING")
            block_counter += 1
            return f"Blocked: Port {port} not allowed"

        log_message(f"Allowed: Packet from {src_ip} to {dst_ip} on port {port}", "INFO")
        return f"Allowed: Packet from {src_ip} to {dst_ip} on port {port}"

    log_message("Blocked: Non-IP packet", "WARNING")
    block_counter += 1
    return "Blocked: Non-IP packet"

def process_packet(packet):
    result = firewall(packet)
    if "Blocked" in result:
        print(f"{result}")
    elif "Allowed" in result:
        print(f"{result}")

log_message("Starting live packet capture...")
try:
    sniff(filter="ip", prn=process_packet, store=False)  # Captures IP packets only
except KeyboardInterrupt:
    log_message("Live packet capture stopped by user.", "INFO")

# Summary after capture
log_message(f"Summary: Total blocked packets: {block_counter}", "INFO")

if block_counter >= ALERT_THRESHOLD:
    log_message(f"ALERT: High number of blocked packets ({block_counter})", "CRITICAL")

log_message(f"Log saved to {log_file_path}", "INFO")
