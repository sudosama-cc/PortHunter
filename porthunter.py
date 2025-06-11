from scapy.all import IP, TCP, sr
import sys

def show_banner():
    banner = r"""
  _____           _   _    _             _            
 |  __ \         | | | |  | |           | |           
 | |__) |__  _ __| |_| |__| |_   _ _ __ | |_ ___ _ __ 
 |  ___/ _ \| '__| __|  __  | | | | '_ \| __/ _ \ '__|
 | |  | (_) | |  | |_| |  | | |_| | | | | ||  __/ |   
 |_|   \___/|_|   \__|_|  |_|\__,_|_| |_|\__\___|_|   
                                                      
 created by sudosama-zsh |  waste packets, not time.
    """
    print(banner)

def syn_scan(target_ip, ports):
    open_ports = []
    packets = []

    print(f"[*] Sending SYN packets to {target_ip}...")

    for port in ports:
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        packets.append(pkt)

    ans, _ = sr(packets, timeout=1, verbose=0)

    for sent, received in ans:
        if received.haslayer(TCP) and received[TCP].flags == 0x12:
            print(f"[+] Open port: {sent[TCP].dport}")
            open_ports.append(sent[TCP].dport)

    print(f"\n[✔] Scan complete. {len(open_ports)} open ports found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 porthunter.py <target_ip>")
        sys.exit(1)

    show_banner()
    target = sys.argv[1]
    ports = list(range(1, 65536))
    syn_scan(target, ports)
