from scapy.all import ARP, Ether, srp, arping
import netifaces
import time

def get_own_ip(interface='eth0'):
    try:
        ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
        return ip, mac
    except (ValueError, KeyError):
        return None
    
def get_host_ip(devices):
    for item in devices:
        if not item["mac"].lower().startswith("08:00:27"):
            devices.remove(item)
            return item["ip"], item["mac"]


def scan_network(subnet="192.168.56.0/24"):
    own_ip, own_mac= get_own_ip()
    answered, _ = arping(subnet, timeout=2, verbose=False)

    devices = []

    for snd, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc
    
        response_time = rcv.time - snd.sent_time
        # if has_any_open_port(ip):
        devices.append({"ip":ip, 
                        "mac":mac,
                        "response":response_time})

    devices.sort(key=lambda x: x["response"])

    host_ip, host_mac = get_host_ip(devices)
    # devices.append({"ip":own_ip, "mac": own_mac})
    devices.append({"ip":host_ip, "mac": host_mac})

    # print(f"[*] Scanning subnet {subnet}...")
    # arp = ARP(pdst=subnet)
    # ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # packet = ether / arp

    # result = srp(packet, timeout=2, verbose=False)[0]

    # devices = []
    # devices.append({"ip":own_ip, "mac":own_mac})
    # for sent, received in result:
    #     # if received.psrc != own_ip:
    #     devices.append({"ip":received.psrc,
    #                     "mac": received.hwsrc})

    print(f"[+] Found {len(devices)} devices.")
    return devices