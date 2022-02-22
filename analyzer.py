from scapy.all import *
import re
from datetime import datetime, timedelta
import socket
import ip_mal

class Analyzer():
    """packet analyzer itself"""	

    @staticmethod
    def find_session(pkts, IP_addr):
        """to get pkts related to specific IP"""
        session = {}
        for pkt in pkts:
            if pkt.haslayer(IP):
                if pkt[IP].src == IP_addr:
                    seg = pkt[IP].payload.name
                    time = str(datetime.fromtimestamp(float(pkt.time)))
                    session[f"{seg}: {pkt[IP].src} --> {pkt[IP].dst}"] = time
                elif pkt[IP].dst == IP_addr:
                    seg = pkt[IP].payload.name
                    time = str(datetime.fromtimestamp(float(pkt.time)))
                    session[f"{seg}: {pkt[IP].dst} <-- {pkt[IP].src}"] = time
                else:
                    continue
            else:
                continue
        result_d = {value : key for (key, value) in session.items()}
        sort = sorted(result_d)
        result = []
        for i in sort:
            result.append(f"{i}  {result_d[i]}")
        result = "\n".join(result)
        result = "\n\n".join((f"Unique connections from {IP_addr} OR to {IP_addr} sorted by time", result))
        return result

    @staticmethod
    def session(pkts, IP_addr_1, IP_addr_2):
        """to get pkts related to specific session between 2 ip"""
        session = []
        packets = PacketList()
        for pkt in pkts:
            if pkt.haslayer(IP) and not pkt.haslayer(ICMP):
                if pkt[IP].src == IP_addr_1 and pkt[IP].dst == IP_addr_2:
                    time = datetime.fromtimestamp(float(pkt.time))
                    seg = pkt[IP].payload.name
                    sport = pkt[seg].sport
                    dport = pkt[seg].dport
                    p_number = pkts.index(pkt)+1
                    session.append(f"#{p_number} {time}  {seg}:  {pkt[IP].src}:{sport} --> {pkt[IP].dst}:{dport}")
                    packets.append(pkt)
                elif pkt[IP].src == IP_addr_2 and pkt[IP].dst == IP_addr_1:
                    time = datetime.fromtimestamp(float(pkt.time))
                    seg = pkt[IP].payload.name
                    sport = pkt[seg].sport
                    dport = pkt[seg].dport
                    p_number = pkts.index(pkt)+1
                    session.append(f"#{p_number} {time}  {seg}:  {pkt[IP].dst}:{dport} <-- {pkt[IP].src}:{sport}")
                    packets.append(pkt)
                else:
                    continue
            elif pkt.haslayer(IP) and pkt.haslayer(ICMP):
                if pkt[IP].src == IP_addr_1 and pkt[IP].dst == IP_addr_2:
                    time = datetime.fromtimestamp(float(pkt.time))
                    seg = pkt[IP].payload.name
                    p_number = pkts.index(pkt)+1
                    session.append(f"#{p_number} {time}  {seg}:  {pkt[IP].src} --> {pkt[IP].dst}")
                    packets.append(pkt)
                elif pkt[IP].src == IP_addr_2 and pkt[IP].dst == IP_addr_1:
                    time = datetime.fromtimestamp(float(pkt.time))
                    seg = pkt[IP].payload.name
                    p_number = pkts.index(pkt)+1
                    session.append(f"#{p_number} {time}  {seg}:  {pkt[IP].dst} <-- {pkt[IP].src}")
                    packets.append(pkt)
                else:
                    continue
            else:
                continue
        session = "\n".join(session)
        result = "\n\n".join((f"Packets exchange between {IP_addr_1} and {IP_addr_2}", session))
        return result, packets
    
    @staticmethod
    def list_of_IP(pkts):
        """private and public IP"""
        unique_ip = []
        private_ip = []
        public_ip = {}
        dns_A = PacketList()
        dns_ans = {}
        prv_ip = re.compile(r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|2([0-9])|(3[0-2]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})")
        for p in pkts[IP]:
            if p.haslayer(IP):
                f = p[IP]
                src = f[IP].src
                dst = f[IP].dst
                unique_ip.append(src)
                unique_ip.append(dst)
                if f.payload.name == "UDP" and f[UDP].sport == 53 and f[DNS].an != None and f[DNS].an.type == 1:
                    dns_A.append(p)
        for i in set(unique_ip):
            mo = prv_ip.search(i)
            if mo == None:
                public_ip[i] = ''
            else:
                private_ip.append(mo.group())
        for p in dns_A:
            dns_ans[p[DNS].an.rdata] = p[DNS].an.rrname.decode("utf-8")
        for i in dns_ans.keys():
            if i in public_ip:
                public_ip[i] = dns_ans[i]
        private_ip = "\n".join(private_ip)
        result = "\n\n".join(("Private IP addresses", private_ip))
        public = []
        for i in public_ip:
            if public_ip[i] == '':
                public.append(f"{i}: --")
            else:
                public.append(f"{i}: {public_ip[i]}")
        public = "\n".join(public)
        result = "\n\n".join((result, "Public IP addresses", public))
        return result

    @staticmethod
    def get_MAC(pkts):
        """get MAC add table"""
        mac = {}
        for p in pkts:
            if p.haslayer(ARP):
                mac[p.psrc] = p.hwsrc
        result = []
        for i in mac:
            result.append(f"{i} -- {mac[i]}")
        result = "\n".join(result)
        result = "\n\n".join(("MAC addresses table:\n\nIP address      MAC address", result))
        return result

    @staticmethod
    def save_txt(result, filename):
        """save txt result"""
        filename = filename + '.txt'
        path = os.path.join(os.getcwd(), filename)
        with open(path, 'w') as file_obj:
            file_obj.write(result)
	
    @staticmethod
    def save_pcap(pkts, filename):
        """save pcap result"""
        filename = filename + '.pcap'
        path = os.path.join(os.getcwd(), filename)
        wrpcap(path, pkts)
		
    @staticmethod
    def get_service(pkts):
        """list of services"""
        ports = []
        port_to_serv = []
        for p in pkts:
            if p.haslayer(TCP) or p.haslayer(UDP):
                src = int(p.sport)
                if src < 2000:
                    ports.append(src)
        ports = list(set(ports))
        for i in ports:
            try:
                s = socket.getservbyport(i)
                port_to_serv.append(f"Port {i}: service {s}")
            except:
                continue
        result = "\n".join(port_to_serv)
        result = "\n\n".join(("Port numbers to service names:", result))
        return result

    @staticmethod
    def malicious_ip(pkts):
        """check for malicious ip addresses"""
        ip_add = []
        result = []
        for i in pkts:
            if i.haslayer(IP):
                ip_add.append(i[IP].src)
                ip_add.append(i[IP].dst)
            else:
                continue
        ip_add = list(set(ip_add))
        for i in ip_add:
            if i in ip_mal.ip_list:
                result.append(i)
        if len(result) == 0:
            return "No malicious IP addresses found"
        else:
            result = "\n".join(result)
            result = "\n\n".join(("Malicious IP", result))
            return result

    @staticmethod
    def time_filter(pkts, date1, date2):
        """to get pkts filter by date"""
        filtered_pkts = []
        filtered_pcap = PacketList()
        for p in pkts:
            p_time = datetime.fromtimestamp(float(p.time))
            time = str(p_time)
            if date1 <= p_time <= (date2 + timedelta(seconds=1)):
                if p.haslayer(IP):
                    filtered_pkts.append(f"{time} {p[IP].payload.name}:  {p[IP].src} -> {p[IP].dst}")
                    filtered_pcap.append(p)
                elif p.haslayer(ARP)and not p.haslayer(IP):
                    filtered_pkts.append(f"{time} {p.payload.name}: {p.src} -> {p.dst}")
                    filtered_pcap.append(p)
        result = "\n".join(filtered_pkts)
        result = "\n\n".join((f"from {date1}", result))
        return result, filtered_pcap
