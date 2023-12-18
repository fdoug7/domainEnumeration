#!/usr/bin python3

# Improvements:
# List should be a dictionary that matches the MX record to their IP

import argparse
import sys,os,json
import dns.resolver as dr
import nmap as nm  


domains = []
serverNames = []

nmScan = nm.PortScanner()
port = 25


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Domain enumeration tool'

    )

    parser.add_argument('-s', '--spfrecords', help='returns SPF records under the given domain')
    parser.add_argument('-m', '--mxrecords', help='Returns the MX records under the given domain')
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-f', '--file', help='File')
    args = parser.parse_args()

    print(args)

    


class domainEnumer:

    def getMXDN():
        if args.file:
            domain_list_file=args.file
            if not os.path.exists(domain_list_file):
                print(f"The path {domain_list_file} doesn't contain a file")
                
            with open(domain_list_file, 'r') as f:
                for line in f.readlines():
                    domains.append(line.strip())

        elif args.domain:
            domains.append(args.domain)
            
        
        else:
            print('Missing potential arguments.')
            sys.exit(1)


        if domains:
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
                except dr.NoAnswer:
                    print('Error querying the domain')
                except dr.NXDOMAIN:
                    print('DNS query name does not exist')  
            print('Server MX names found: \b')
            for i in serverNames:
                print(f'{i}')  
        else:
            print('No domains provided')


    def getIP():
        serverIP = []
        for name in serverNames:
            for y in dr.resolve(name, 'A'):
                z = y.to_text()
                serverIP.append(z)
        serverIP = list(set(serverIP)) 
        return serverIP


    def serverScan():
        for ip in domainEnumer.getIP():
            print('='*30)
            nmScan.scan(ip, str(port))
            
            print("IP: " + ip)
            print("IP Status: ", nmScan[ip].state())
            print("Port state: ", nmScan[ip]['tcp'][port]['state'] if nmScan[ip].get('tcp')  else "")
            print('\b')


domainEnumer.getMXDN()
domainEnumer.serverScan()
# getMXDN()
# serverScan()