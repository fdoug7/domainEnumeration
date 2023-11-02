#!/usr/bin/env python

# Improvements:
# List should be a dictionary that matches the MX record to their IP

import sys,os
import dns.resolver as dr
import nmap as nm  

domains = []
serverNames = []

nmScan = nm.PortScanner()
ports = '25'

def getMXDN(): 
    for domain in domains:
        print('\b')
        print('='*30)
        print(f'{domain}')
        print('-'*30)
        try:
            for x in dr.resolve(domain, 'MX'):
                t = x.to_text()
                i = t.find(' ')
                n = t[i+1:-1]
                serverNames.append(n)
                print(n)
        except dr.NoAnswer:
            print('Error querying the domain')
        except dr.NXDOMAIN:
            print('DNS query name does not exist')  
    print('Server MX names found: \b' + str(serverNames) + '\b')
    print('\b')  


def getIP():
    serverIP = []
    for name in serverNames:
        for y in dr.resolve(name, 'A'):
            z = y.to_text()
            serverIP.append(z)
    serverIP = list(set(serverIP)) 
    return serverIP


def serverScan():
    for ip in getIP():
        print('='*30)
        nmScan.scan(ip, ports)
        
        print("IP: " + ip)
        try:
            print("IP Status: ", nmScan[ip].state())
            print("Port open: ", nmScan[ip]['tcp'].keys())
            print('\b')

        except KeyError:
            print("KeyError Exception found. Not sure of the cause")


if len(sys.argv) > 1:
    #expect file path
    domain_list_file=sys.argv[1]
    if not os.path.exists(domain_list_file):
        print(f"The path {domain_list_file} doesn't contain a file")
        sys.exit(1)
    
    with open(domain_list_file,'r') as f:
        for line in f.readlines():
            domains.append(line)
else:
    print(f"Missing positional argument domain_list_file.\nPlease specify path to a file containing new line delimitated domain names")
    sys.exit(1)            
getMXDN()
serverScan()