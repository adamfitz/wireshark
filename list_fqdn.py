"""
Script Name:    list_fqdn.py
Author:         Fitzi
Purpose:        Script reads the provided wireshark packet capture file , iterate all DNS packets and returns any FQDN
                found in the DNSQR record.
"""

import sys
from scapy.all import *
from scapy.layers.dns import DNSQR

def main(file_name):
    fqdn_list = []

    # load the capture file
    capture_data = rdpcap(file_name)

    # return all fqdns from DNS query packets
    for packet in capture_data:
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode('utf-8')
            fqdn_list.append(qname.rstrip('.'))

    # remove any reoccuring fqdns (make a unique list)
    unique_fqdns = set()
    unique_list = []

    for fqdn in fqdn_list:
        if fqdn not in unique_fqdns:
            # remove any domains local to the LAN / subnet
            if '.local' not in fqdn:
                unique_fqdns.add(fqdn)
                unique_list.append(fqdn)

    # list all found fqdns

    print(f'\nList of FQDNs found in: {file_name}:')
    print('=' * 50)
    for element in unique_fqdns:
        print(element)


def usage():
    # string is purposley un-indented to align left in stdout
    help = """
File name parameter is required.

Usage: 
list_fqdn.py $pcap_file_name

Example:
list_fqdn.py my_capture.pcap
list_fqdn.py my_capture.pcapng
    """
    print(help)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        usage()
    else:
        file_name = sys.argv[1]
        main(file_name)
