print("Welcome to ArmorNet")
import time
import json
from arpSpoofing_handle import restore_arp, blackList_machine, remove_from_blacklist
from datetime import datetime
from shutdown import shutdown_connection
from getIPs import scan_network
from api_comm import send_data_to_api
from scapy.all import sniff, wrpcap, IP, TCP, ARP
import threading

iface = "eth0"
max_packets = 30
max_time =100

start_time = time.time()
packet_counter = 0
captured_flows = []
pcap_files = {}
packet_counters = {}

log_data = {
    "productId": "NS-0x2",
    "product_details": {
        "color": "navy blue",
        "type": "active defence"
    },
    "projectId": "project-42",
    "project_details": {
        "name": "ArmorNet",
        "desc": "Sniff. Detect. Terminate"
    }, 
    "assets": [],
    "metadata": [],
    "alerts": []
}

log_lock = threading.Lock()

# get all the connected ip in the network except the sniffers ip
arp_table = scan_network()

host = arp_table[len(arp_table)-1]["ip"]
host_mac = arp_table[len(arp_table)-1]["mac"]
print(f"the assets are {arp_table}")

# def should_stop(stamp):
#     return packet_counter >= max_packets or (time.time() - stamp) >= max_time

def packet_callback(packet):
    global packet_counter
    print(packet.summary())

    if packet.haslayer(IP):
        ip = packet[IP].src
        mac = packet.src
        ttl = packet[IP].ttl

        with log_lock:
            if not any(asset["ip"] == ip for asset in log_data["assets"]):
                log_data["assets"].append({
                    "asset-id":f"as-{len(log_data["assets"])+1}",
                    "ip": ip,
                    "mac": mac,
                    "os": "Cisco/Embedded" if ttl >= 254 else 
                           "Windows" if ttl >= 128 else 
                           "Linux/macOS" if ttl >= 64 else "Unknown",
                    "packets": 0,
                    "pcap_file": f"{ip}.pcap"
                })
                pcap_files[ip] = []
                packet_counters[ip] = 0

            packet_counters[ip] += 1
            for asset in log_data["assets"]:
                if asset["ip"] == ip:
                    asset["packets"] = packet_counters[ip]
                    break
            # log_data["assets"]["packets"] = packet_counters[ip]
            pcap_files[ip].append(packet)
        
    if packet.haslayer(TCP):
        packet_ip = packet[IP]
        packet_mac = packet.src
        tcp = packet[TCP]

        with log_lock:
            log_data["alerts"].append ({
                "type": "TCP protocol",
                "ip": packet_ip.src,
                "mac": packet_mac,
                "sport": tcp.sport,
                "dastanation": packet_ip.dst,
                "dport": tcp.dport,
                "created": time.time()
            })
            captured_flows.append((packet_ip.src, packet_ip.dst, tcp.sport, tcp.dport, tcp.seq, tcp.ack))

            print(f"[!] TCP packet Detected! IP: {packet_ip}")
            print(f"{packet_ip.src}:{tcp.sport} → {packet_ip.dst}:{tcp.dport}")

            # Shutdown the connection between two assets
            # if packet_counter >= max_packets or (time.time() - stamp) >= max_time:
            #     shutdown_connection(host, packet_ip.src, captured_flows)
            #     print("[✔] Connection reset complete.")

    elif packet.haslayer(ARP) and packet[ARP].op == 2:
        ip_check = packet[ARP].psrc
        mac_check = packet[ARP].hwsrc

        with log_lock:
            for device in arp_table: 
                if ip_check == device["ip"] and device["mac"] != mac_check:
                    log_data["alerts"].append ({
                        "type": "ARP spoofing",
                        "ip": ip_check,
                        "original mac": device["mac"],
                        "spoofed mac": mac_check,
                        "created": datetime.now().isoformat()
                    })
                    print(f"[!] ARP Spoofing Detected! IP {ip_check} is being claimed by multiple MACs:")
                    print(f"    - Original MAC: {device["mac"]}")
                    print(f"    - Spoffing MAC: {mac_check}")

                    #restore the correct ip and macs
                    restore_arp(host, host_mac, ip_check, device["mac"])
                    #black list the attacker
                    blackList_machine(mac_check)
                    log_data["alerts"].append({
                        "type": "Black listed machine",
                        "mac": mac_check,
                        "created": datetime.now().isoformat()
                    })
                    # #remove from blacklist
                    # remove_from_blacklist(mac)


    else:
        with log_lock:
            log_data["metadata"].append({
                "meta-id":f"as-{len(log_data["metadata"])+1}",
                "meta-name":f"nm-{len(log_data["metadata"])+10}",
                "ip": packet[IP].src if packet.haslayer(IP) else "Unknown",
                "mac": packet.src if packet.src else "Unknown",
                "desc": packet.summary()
            })

def save_json():
    with log_lock:
        with open("sniffed_data.json", "w") as f:
            json.dump(log_data, f, indent =4)

def sniff_thread(target_ip):
    print(f"[*] Sniffing on {iface} for up to {max_packets} packets or {max_time} seconds...")
    packets = sniff(
        iface = iface, 
        filter = f"(arp or ip) and host {host} and host {target_ip}",
        prn=packet_callback, 
        store=True,
        # stop_filter=lambda x: should_stop()
    )
    # Shutdown the connection between two assets
    # shutdown_connection(host, target_ip, captured_flows)
    wrpcap(f"capture_{target_ip}.pcap", packets)

#start thread
threads = []
arp_table_trim = arp_table[:-1]
for device in arp_table_trim:
    t = threading.Thread(target=sniff_thread, args=(device["ip"],), name=f"sniffer-{device["ip"]}")
    t.start()
    threads.append(t)

#wait for all threads to finish
try:
    for t in threads:
        t.join()
except:
    save_json()
    # send_data_to_api()





