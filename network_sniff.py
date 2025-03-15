from scapy.all import sniff, wrpcap, rdpcap, IP, ICMP, get_if_list

def sniffPckt(pkt):
    pkt.show()

def startSniff():
    iface_list = get_if_list()
    print("Kullanılabilir Arayüzler:", iface_list)
    iface = input("Kullanılacak arayüzü girin: ") if iface_list else "eth0"

    scapy_sniff = sniff(prn=sniffPckt, timeout=50, iface=iface, stop_filter=lambda x: x.haslayer(ICMP))
    wrpcap("targetInfo.pcap", scapy_sniff)

def start_read():
    scapy_cap = rdpcap("targetInfo.pcap")
    ipList = list({pckt[IP].src for pckt in scapy_cap if IP in pckt})
    print("Tespit edilen IP adresleri:", ipList)

print("""
    1: sniff
    2: read
""")

choice = input(">> ")

if choice == "1":
    startSniff()
elif choice == "2":
    start_read()
else:
    print("Hatalı giriş")
