#!/usr/bin/env

# Improvements:
# List should be a dictionary that matches the MX record to their IP

import dns.resolver as dr   # pip install dnsresolver
import nmap as nm           # pip install nmap-python


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

getMXDN()
serverScan()



