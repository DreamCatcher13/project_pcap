from scapy.all import *
import re
from datetime import datetime
import os
import argparse
from analyzer import Analyzer

def save_result_txt(result):
    """ask if user wants to save result in txt file"""
    print(f"\n{result}\n")
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
    return user_choice
	
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
time1 = datetime.fromtimestamp(float(pkts[0].time))
time2 = datetime.fromtimestamp(float(pkts[-1].time))
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
		user_choice = save_result_txt(result)
	elif user_choice == '2':
		result = analyzer.get_MAC(pkts)
		user_choice = save_result_txt(result)
	elif user_choice == '3':
		ip = input("Enter IP address: ")
		if ip not in ip_list:
			print("IP address is not in packet file.")
			print('\n' + what_to_do)
			user_choice = input("Select a function: ")
		else:
			result = analyzer.find_session(pkts, ip)
			user_choice = save_result_txt(result)
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
		user_choice = save_result_txt(result)
	else:
		result = analyzer.get_service(pkts)
		user_choice = save_result_txt(result)

