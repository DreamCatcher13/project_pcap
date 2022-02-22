from scapy.all import *
import re
from datetime import datetime, timedelta
import os
import argparse
from analyzer import Analyzer

def time_in_range(start, end, given):
    """check if given time is in range [start, end]"""
    end = end + timedelta(seconds=1)
    return start <= given <= end

def get_user_choice():
    """what function to execute"""
    print('\n' + what_to_do)
    user_choice = input("Select a function: ")
    return user_choice
    
def save_result_txt(result):
    """ask if user wants to save result in txt file"""
    print(f"\n{result}\n")
    print('Do you want to save the result in txt file? yes/no')
    s = input('Answer: ')
    if s == 'yes':
        filename = input('Enter the name of the file: ')
        analyzer.save_txt(result, filename)
        print('File saved')
        user_choice = get_user_choice()
    else:
        user_choice = get_user_choice()
    return user_choice

def save_txt_or_pcap(result, packets):
    """ask if user wants to save result in txt file or pcap file"""
    print(f"\n{result}\n")
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
            user_choice = get_user_choice()
        else:
            user_choice = get_user_choice()
    else:
        print('Do you want to save the packets exchange in pcap file? yes/no')
        sp = input('Answer: ')
        if sp == 'yes':
            filename = input('Enter the name of the file: ')
            analyzer.save_pcap(packets, filename)
            print('File saved')
            user_choice = get_user_choice()
        else:
            user_choice = get_user_choice()
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
[7] List all IP and ARP packets in a given time period
[8] Exit
'''
print(what_to_do)
time_filter_warning = '''
WARNING !!!
You should enter date/time exactly as in the example:
  2021-10-31 06:34:12
Otherwise, the program will crash
Be aware that the function does not include miliseconds
The end_date can be 1 second greater to get packets from the end of the file
'''

user_choice = input("Select a function: ")

while (user_choice != '8'):
    if user_choice not in ['1', '2', '3', '4', '5', '6', '7']:
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
            user_choice = get_user_choice()
        else:
            result = analyzer.find_session(pkts, ip)
            user_choice = save_result_txt(result)
    elif user_choice == '4':
        ip1 = input("Enter first IP address: ")
        ip2 = input("Enter second IP address: ")
        if ip1 not in ip_list or ip2 not in ip_list:
            print("IP address is not in packet file.")
            user_choice = get_user_choice()
        else:
            result, packets = analyzer.session(pkts, ip1, ip2)
            user_choice = save_txt_or_pcap(result, packets)
    elif user_choice == '5':
        result = analyzer.malicious_ip(pkts)
        user_choice = save_result_txt(result)
    elif user_choice == '6':
        result = analyzer.get_service(pkts)
        user_choice = save_result_txt(result)
    else:
        print(time_filter_warning)
        begin_date = input("Enter start date/time: ")
        end_date = input("Enter end date/time: ")
        begin_date = datetime.strptime(begin_date, "%Y-%m-%d %H:%M:%S")
        end_date = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")
        if not time_in_range(time1, time2, end_date):
            print("Date/time not in packet file")
            user_choice = get_user_choice()
        else:
            result, packets = analyzer.time_filter(pkts, begin_date, end_date)
            user_choice = save_txt_or_pcap(result, packets)

