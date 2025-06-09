from scapy.all import IP, TCP, send

def shutdown_connection(src, dst, sport, dport, seq, ack):
    print(f"[!] SSH suspicious usage Detected! From {src} sending too much SSH packets!")
    print(f"[!] Injecting TCP RSTs to terminate connections between {src} and {dst}")
    rst1 = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="R", seq=seq)
    send(rst1, verbose=False)
    rst2 = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="R", seq=ack)
    send(rst2, verbose=False)
    print("[!] Connection terminated")

    
