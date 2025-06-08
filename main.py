print("Welcome to ArmorNet")
import time
from datetime import datetime
import json
from arpSpoofing_handle import restore_arp, blackList_machine, remove_from_blacklist
from datetime import datetime
from shutdown import shutdown_connection
from getIPs import scan_network
from api_comm import send_data_to_api
from scapy.all import sniff, wrpcap, IP, TCP, ARP
import threading

iface = "eth0"
max_packets = 50
max_time =10

start_time = time.time()
packet_counter = 0
captured_flows = {}
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

arp_table_dict = {device["ip"]: device for device in arp_table}
print(f"the assets are {arp_table}")

def packet_callback(packet):
    global packet_counter
    print(packet.summary())

    if packet.haslayer(IP):  #Checking for IP layer
        ip = packet[IP].src
        mac = packet.src

        with log_lock:
            if not any(asset["ip"] == ip for asset in log_data["assets"]):   #Get the assets
                log_data["assets"].append({
                    "asset-id":f"as-{len(log_data["assets"])+1}",
                    "ip": ip,
                    "mac": mac,
                    "name": arp_table_dict[ip]["name"],
                    "os": arp_table_dict[ip]["OS"],
                    "type": arp_table_dict[ip]["type"], 
                    "pcap_file": f"{ip}.pcap"
                })

                log_data["metadata"].append({                               #Get the metadata
                    "asset-id":f"as-{len(log_data["assets"])}",
                    "meta-id":f"mt-{len(log_data["metadata"])+1}",
                    "meta-name":f"nm-{len(log_data["metadata"])+10}",
                    "ip": ip,
                    "packets": 0,
                    "open ports": arp_table_dict[ip]["open_ports"],
                    "services": arp_table_dict[ip]["sefvices"],
                })
                pcap_files[ip] = []
                packet_counters[ip] = 0

            packet_counters[ip] += 1
            for asset in log_data["metadata"]:                              #Count and add the paackets
                if asset["ip"] == ip:
                    asset["packets"] = packet_counters[ip]
                    break
            pcap_files[ip].append(packet)
        
    if packet.haslayer(TCP):            #Checking for TCP layer                                               
        packet_ip = packet[IP]
        packet_mac = packet.src
        tcp = packet[TCP]

        with log_lock:
            log_data["alerts"].append ({                                    #Get the TCP alert
                "alert_name": "TCP protocol",
                "ip": packet_ip.src,
                "mac": packet_mac,
                "sport": tcp.sport,
                "destination": packet_ip.dst,
                "dport": tcp.dport,
                "severity": 2,
                "created": datetime.now().isoformat()
            })

            if tcp.dport == 22 or tcp.sport == 22:                          #Check for port 22 (ssh connection)
                flow_key = tuple(sorted([packet_ip.src, packet_ip.dst]))

                if flow_key not in captured_flows:
                    captured_flows[flow_key] ={
                        "count": 1,
                        "start": time.time(),
                        "sport": tcp.sport,
                        "dport": tcp.dport
                    }
                else:
                    flow = captured_flows[flow_key]
                    flow["count"] += 1
                    duration = time.time() - flow["start"]
                    if flow["count"] >= max_packets and duration >= max_time:  #ssh connection termination
                        shutdown_connection(packet_ip.src, packet_ip.dst, tcp.sport, tcp.dport, tcp.seq, tcp.ack)
                        print("[✔] Connection reset complete.")
                        
                        log_data["alerts"].append ({
                            "alert_name": "SSH suspicious usage",
                            "ip": packet_ip.src,
                            "sport": tcp.sport,
                            "destination": packet_ip.dst,
                            "dport": tcp.dport,
                            "mitre_tactic": "Persistence, Privilege Escalation",
                            "mitre_technique": "(T1098.004) Account Manipulation: SSH Authorized Keys",
                            "severity": 4,
                            "created": datetime.now().isoformat()
                        })

                        del captured_flows[flow_key]

    elif packet.haslayer(ARP) and packet[ARP].op == 2:      #ARP Detection
        ip_check = packet[ARP].psrc
        mac_check = packet[ARP].hwsrc

        with log_lock:
            for device in arp_table: 
                if ip_check == device["ip"] and device["mac"] != mac_check:
                    log_data["alerts"].append ({
                        "alert_name": "ARP spoofing",
                        "ip": ip_check,
                        "original mac": device["mac"],
                        "spoofed mac": mac_check,
                        "mitre_tactic":"Credential Access, Collection",
                        "mitre_technique": "(T1557) Adversary-in-the-Middle: ARP Cache Poisoning",
                        "severity": 5,
                        "created": datetime.now().isoformat()
                    })
                    print(f"[!] ARP Spoofing Detected! IP {ip_check} is being claimed by multiple MACs:")
                    print(f"    - Original MAC: {device["mac"]}")
                    print(f"    - Spoffing MAC: {mac_check}")
                   
                    restore_arp(host, host_mac, ip_check, device["mac"])            #restore the correct ip and macs
                    
                    blackList_machine(mac_check)                                    #black list the attacker
                    # print(f"{mac_check} was blacklisted!!")
                    # log_data["alerts"].append({
                    #     "type": "Black listed machine",
                    #     "mac": mac_check,
                    #     "created": datetime.now().isoformat()
                    # })
                    # #remove from blacklist
                    # remove_from_blacklist(mac)
    else:                                                                           #Record any "undefiend metadata"   
        with log_lock:
            as_id = "None"
            for asset in log_data["assets"]:
                if packet.haslayer(IP):
                    as_id = asset["asset-id"] if asset["ip"] == packet[IP].src else "None"
            log_data["metadata"].append({
                "asset-id": as_id,
                "meta-id":f"as-{len(log_data["metadata"])+1}",
                "meta-name":f"nm-{len(log_data["metadata"])+10}",
                "ip": packet[IP].src if packet.haslayer(IP) else "None",
                "desc": packet.summary()
            })
    if packet.haslayer(IP):     
        pcap_files[ip].append(packet)

def save_json():                                                                    #Save to a json file
    with log_lock:
        with open("sniffed_data.json", "w") as f:
            json.dump(log_data, f, indent =4)

def sniff_thread(target_ip):
    print(f"[*] Sniffing on {iface} for up to {max_packets} packets or {max_time} seconds...")
    packets = sniff(
        iface = iface, 
        # filter = f"(arp or ip) and host {host} and host {target_ip}",
        filter = f"(arp or ip) and ((src host {host} and dst host {target_ip}) or (src host {target_ip} and dst host {host}))",
        prn=packet_callback, 
        store=True,
        # stop_filter=lambda x: should_stop()
    )


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
    # for asset in pcap_files:
    #     wrpcap(f"capture_{asset}.pcap", pcap_files[asset])
    # save_json()
    # send_data_to_api()
    print("FINISHED!")





