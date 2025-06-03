from scapy.all import ARP, send
import subprocess

def restore_arp(target_ip, target_mac, source_ip, source_mac):
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    send(pkt, count=5, verbose=False)
    print(f"[+] Sent ARP restoration: {source_ip} is at {source_mac} to {target_ip}")


def blackList_machine(mac):
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        print(f"[!] Black listed MAC {mac} using iptables")


def remove_from_blacklist(mac):
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", mac, "-j", "DROP"])
        print(f"[!] {mac} Was removed from Black list")