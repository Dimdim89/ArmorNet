from scapy.all import ARP, Ether, srp, arping, get_if_addr, get_working_if
import subprocess
import re
    
def get_host_ip(devices):
    for item in devices:
        if not item["mac"].lower().startswith("08:00:27"):
            devices.remove(item)
            devices.append(item)


def scan_network(subnet=None):
    if subnet is None:
        # Get the current working interface
        interface = get_working_if()
        # Get the IP address of the current interface
        subnet = get_if_addr(interface)+ "/24"
    answered, _ = arping(subnet, timeout=2, verbose=False)
    devices = []

    for snd, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc   
        response_time = rcv.time - snd.sent_time

        #make a deep scan for each machine (nmap).
        # find: OS, hostname, open ports 
        try:
            open_ports = []
            services = []
            result = subprocess.run(
                ["nmap", "-O", "-sV", "--script=nbstat,smb-os-discovery", ip],
                capture_output=True, text=True, timeout=60
            )
            output = result.stdout
            get_os = re.search(r'OS details: (.+)', output) if re.search(r'OS details: (.+)', output) else re.search(r'OS CPE: (.+)', output)
            os = get_os.group(1) if get_os != None else "Unknown" 
            get_hostname = re.search(r'NetBIOS name:\s+([^,\n\r]+)', output) if re.search(r'NetBIOS name:\s+([^\n\r]+)', output) else re.search(r'hostname:\s+([^,\n\r]+)', output)                                   
            hostname = get_hostname.group(1) if get_hostname != None else "None"
            get_device_type = re.search(r'Device type: (.+)', output)
            device_type = get_device_type.group(1) if get_device_type != None else "None"
            port_lines = re.findall(r'(\d+/tcp)\s+open\s+(\S+)\s+(.*)', output)

            for port, service, version in port_lines:
                open_ports.append(port)
                services.append({
                    "port": port,
                    "service": service,
                    "version": version.strip()
                })

            devices.append({"ip":ip, 
                            "mac":mac,
                            "name":hostname,
                            "OS": os,
                            "type": device_type,
                            "open_ports": open_ports,
                            "sefvices": services,
                            "response":response_time})
        
        except Exception as e:
            print(f"Error scanning {ip}: {e}")

    get_host_ip(devices)

    print(f"[+] Found {len(devices)} devices.")
    return devices