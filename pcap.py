from scapy.all import *
import re
import datetime
import os
import argparse
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
                    time = str(datetime.datetime.fromtimestamp(float(pkt.time)))
                    session[f"{seg}: {pkt[IP].src} --> {pkt[IP].dst}"] = time
                elif pkt[IP].dst == IP_addr:
                    seg = pkt[IP].payload.name
                    time = str(datetime.datetime.fromtimestamp(float(pkt.time)))
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
                    time = datetime.datetime.fromtimestamp(float(pkt.time))
                    seg = pkt[IP].payload.name
                    sport = pkt[seg].sport
                    dport = pkt[seg].dport
                    p_number = pkts.index(pkt)+1
                    session.append(f"#{p_number} {time}  {seg}:  {pkt[IP].src}:{sport} --> {pkt[IP].dst}:{dport}")
                    packets.append(pkt)
                elif pkt[IP].src == IP_addr_2 and pkt[IP].dst == IP_addr_1:
                    time = datetime.datetime.fromtimestamp(float(pkt.time))
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
                    time = datetime.datetime.fromtimestamp(float(pkt.time))
                    seg = pkt[IP].payload.name
                    p_number = pkts.index(pkt)+1
                    session.append(f"#{p_number} {time}  {seg}:  {pkt[IP].src} --> {pkt[IP].dst}")
                    packets.append(pkt)
                elif pkt[IP].src == IP_addr_2 and pkt[IP].dst == IP_addr_1:
                    time = datetime.datetime.fromtimestamp(float(pkt.time))
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
            result.append(f"{i}: {mac[i]}")
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


	
## actual program ##

# parser

parser = argparse.ArgumentParser(prog = 'pcap.py',
								 usage = 'python pcap.py [-h] path_to_pcap_file',
								 description = ''' The program pcap.py is used for simple
								 analysis of network traffic file''',
								 epilog='Enjoy the program! :)')
parser.add_argument('file', 
					type = str,
					help = 'The path to a pcap file')
args = parser.parse_args()
path = args.file	

#begin

analyzer = Analyzer()

if not os.path.exists(path):
	print("Wrong path to the file")
	quit()

print("Reading pcap-file...")
pkts = rdpcap(args.file)
pkt_sum = re.compile(r"TCP:.* UDP:.* ICMP:.* Other:\d*")
mo = pkt_sum.search(str(pkts))
time1 = datetime.datetime.fromtimestamp(float(pkts[0].time))
time2 = datetime.datetime.fromtimestamp(float(pkts[-1].time))
print("Short summary:")
print(f"File name: {pkts.listname}\nPackets included: {mo.group()}")
other = []
ip_list = []
for i in pkts:
	if not i.haslayer(IP):
		other.append(i.payload.name)
	elif i.haslayer(IP):
		ip_list.append(i[IP].src)
		ip_list.append(i[IP].dst)
	else:
		continue
print("Other packets: " + ' '.join(set(other)))
print(f"Capture begins: {time1}\nCapture ends: {time2}")
ip_list = list(set(ip_list))

what_to_do = '''
Avaliable function:
[1] List private and public IP addresses from a pcap file
[2] Get MAC addresses from a pcap file - if where are some ARP packets
[3] List all unique sessions related to specific IP address
[4] List all packets between 2 IP addresses
[5] Check for malicious IP addresses 
[6] Get the list of services to which connections were made
[7] Exit
'''
print(what_to_do)

user_choice = input("Select a function: ")

while (user_choice != '7'):
	if user_choice not in ['1', '2', '3', '4', '5', '6']:
		print("Wrong choice")
		user_choice = input("Select a function: ")
	if user_choice == '1':
		result = analyzer.list_of_IP(pkts)
		print('\n' + result + '\n')
		print('Do you want to save the result in txt file? yes/no')
		s = input('Answer: ')
		if s == 'yes':
			filename = input('Enter the name of the file: ')
			analyzer.save_txt(result, filename)
			print('File saved')
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
		else:
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
	elif user_choice == '2':
		result = analyzer.get_MAC(pkts)
		print('\n' + result + '\n')
		print('Do you want to save the result in txt file? yes/no')
		s = input('Answer: ')
		if s == 'yes':
			filename = input('Enter the name of the file: ')
			analyzer.save_txt(result, filename)
			print('File saved')
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
		else:
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
	elif user_choice == '3':
		ip = input("Enter IP address: ")
		if ip not in ip_list:
			print("IP address is not in packet file.")
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
		else:
			result = analyzer.find_session(pkts, ip)
			print('\n' + result + '\n')
			print('Do you want to save the result in txt file? yes/no')
			s = input('Answer: ')
			if s == 'yes':
				filename = input('Enter the name of the file: ')
				analyzer.save_txt(result, filename)
				print('File saved')
				print('\n' + what_to_do)
				user_choice = input("Select a function: ")
			else:
				print('\n' + what_to_do)
				user_choice = input("Select a function: ")
	elif user_choice == '4':
		ip1 = input("Enter first IP address: ")
		ip2 = input("Enter second IP address: ")
		if ip1 not in ip_list or ip2 not in ip_list:
			print("IP address is not in packet file.")
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
		else:
			(result, packets) = analyzer.session(pkts, ip1, ip2)
			print('\n' + result + '\n')
			print('Do you want to save the result in txt file? yes/no')
			s = input('Answer: ')
			if s == 'yes':
				filename = input('Enter the name of the file: ')
				analyzer.save_txt(result, filename)
				print('File saved')
				print('Do you want to save the packets exchange in pcap file? yes/no')
				sp = input('Answer: ')
				if sp == 'yes':
					filename = input('Enter the name of the file: ')
					analyzer.save_pcap(packets, filename)
					print('File saved')
					print('\n' + what_to_do)
					user_choice = input("Select a function: ")
				else:
					print('\n' + what_to_do)
					user_choice = input("Select a function: ")
			else:
				print('Do you want to save the packets exchange in pcap file? yes/no')
				sp = input('Answer: ')
				if sp == 'yes':
					filename = input('Enter the name of the file: ')
					analyzer.save_pcap(packets, filename)
					print('File saved')
					print('\n' + what_to_do)
					user_choice = input("Select a function: ")
				else:
					print('\n' + what_to_do)
					user_choice = input("Select a function: ")
	elif user_choice == '5':
		result = analyzer.malicious_ip(pkts)
		print('\n' + result + '\n')
		print('Do you want to save the result in txt file? yes/no')
		s = input('Answer: ')
		if s == 'yes':
			filename = input('Enter the name of the file: ')
			analyzer.save_txt(result, filename)
			print('File saved')
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
		else:
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
	else:
		result = analyzer.get_service(pkts)
		print('\n' + result + '\n')
		print('Do you want to save the result in txt file? yes/no')
		s = input('Answer: ')
		if s == 'yes':
			filename = input('Enter the name of the file: ')
			analyzer.save_txt(result, filename)
			print('File saved')
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
		else:
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")

