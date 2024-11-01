from scapy.all import *

def tcp_scan(dip, dport):
    # Create TCP SYN packet
    packet = IP(dst=dip)/TCP(sport=random.randint(4000,8000), dport=dport, flags="S")
    
    # Send packet and get response
    response = sr1(packet, timeout=1, verbose=0)
    
    if response is None:
        print(f"Port {dport} is filtered or not responding")
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            print(f"Port {dport} is open")
            send(IP(dst=dip)/TCP(sport=random.randint(4000,8000), dport=dport, flags="R"), verbose=0)
        elif response.getlayer(TCP).flags == 0x14:  # RST
            print(f"Port {dport} is closed")
        else:
            print(f"Port {dport} received unknown response")
    else:
        print(f"Port {dport} error")

    print(f"Received -------------------------------------------------- \n{response}\r\n")

if __name__ == "__main__":
    dip = input("Enter your IP: ")
    dlport = input("Define port list (separate using spaces): ")
    dport = [int(a) for a in dlport.split()]
    
    for port in dport:
        tcp_scan(dip, port)


