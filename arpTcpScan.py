from scapy.all import *
import argparse

def get_arg(): # Gather required info when script is run
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="target", required=True)
    parser.add_argument("-p", "--ports", dest="portRange", required=True)
    opt = parser.parse_args()
    
    if not opt.target or opt.portRange:
        parser.error("[!] Enter valid IP range and port range.")
    return opt


def getRanges(portsToGet): # Add ports to set as singles or range
    
    ports = set()
    
    for port in portsToGet.split(','):
        if '-' in port:
            start_port, end_port = port.split('-')
            ports.update(range(int(start_port), int(end_port)))
        else:
            ports.add(int(port))
    return sorted(ports)


def arpScan(ipTarget): # Scan through the inputted IP/s and log responses into a dict
    
    print("Scanning IP/s...")
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ipTarget), verbose=False, timeout=1)
    
    result =[]
    for i in range(0, len(ans)):
        received_dict = {'ip' : ans[i][1].psrc, 'mac' : ans[i][1].src}
        result.append(received_dict)
    return result


def tcpScan(ipTarget, ports): # Scan through specified port/s using dict of responded IP/s and log port responses into a dict
    
    print("Scanning port/s...")
    result = []
    for i in ipTarget:
        for port in ports:
            ans, unans = sr(IP(dst=i['ip'])/TCP(dport=port, flags="S"), verbose = False, timeout=1)
            if ans:
                for s, r in ans:
                    if r.haslayer(TCP) and r[TCP].flags == 18:
                        port_dict = {'ip' : i['ip'], 'port' : port}
                        result.append(port_dict)
    return result


def display_output(ip_dict, port_dict): # Display results in an organised view, making sure open ports are listed with correct ip
    
    print("Displaying results...")
    ipCount = 0
    for i in ip_dict:
        if (ipCount > len(ip_dict)):
            break
        else:
            print("-"*30 + "\nIP Address\tMAC Address\n" + 30*"-")
            print("{}\t{}".format(i['ip'], i['mac']))
            print("\nPort:\tProtocol:\tStatus:")
            for p in port_dict:
                if i['ip'] == p['ip']:
                    print("{}\t{}\t\t{}".format(p['port'], "TCP", "OPEN"))
            print("\n")
    ipCount=ipCount+1
                

opt = get_arg()
port_input = getRanges(opt.portRange)
scanned_ip_output = arpScan(opt.target)
scanned_port_output = tcpScan(scanned_ip_output, port_input)
display_output(scanned_ip_output, scanned_port_output)