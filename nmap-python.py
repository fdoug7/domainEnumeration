#!/usr/bin python3

# Improvements:
# List should be a dictionary that matches the MX record to their IP

import argparse
import sys,os,json
import dns.resolver as dr
import nmap as nm  



domains = {"domains": {} }
serverNames = []

nmScan = nm.PortScanner()
port = 25


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Domain enumeration tool'

    )

    parser.add_argument('-s', '--spfrecords', action='store_true', help='returns SPF records under the given domain')
    parser.add_argument('-m', '--mxrecords', action='store_true', help='Returns the MX records under the given domain')
    parser.add_argument('-o', '--output', action='store_true', help='Outputs the results to a json file')
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-f', '--file', help='File')
    args = parser.parse_args()


    


class domainEnumer:
    ##Template domain = [["domain": {}, "mxname": {"ip": }]]
    if args.file:
        domain_list_file=args.file
        if not os.path.exists(domain_list_file):
            print(f"The path {domain_list_file} doesn't contain a file")
                
        with open(domain_list_file, 'r') as f:
            for line in f.readlines():
                domains['domains'].update({line.strip(): {}})
                domains['domains'][line.strip()].update({"mxnames": {}})
                    
    elif args.domain:
        domains['domains'].update({args.domain: {}})
        domains['domains'][args.domain].update({"mxnames": {}})
            
    else:
        print('Missing potential arguments.')
        sys.exit(1)

    def getMX():          
        if True:
            for domain in domains['domains']:
                print('\b')
                print('='*30)
                print(f'{domain}')
                print('-'*30)
                try:
                    print('Server MX names found: \b')
                    for x in dr.resolve(domain, 'MX'):
                        t = x.to_text()
                        i = t.find(' ')
                        n = t[i+1:-1]   
                        print(x)     
                        domains['domains'][domain]['mxnames'].update({n: {}})            

                except dr.NoAnswer:
                    print('Error querying the domain')
                except dr.NXDOMAIN:
                    print('DNS query name does not exist')


    def getTXT():        
        try: 
            for domain in domains['domains']:
                print(dr.resolve(domain, 'TXT').rrset)
                y = dr.resolve(domain, 'TXT').rrset
                domains['domains'][domain].update({"TXT Records": []})
                domains['domains'][domain]["TXT Records"].append(str(y))

        except (dr.NoAnswer) as err:
            print(f"{domain}: Unexpected {err=}, {type(err)=}")
        finally: 
            print(domains)


    def getIP():
        for i in domains['domains']:
            for x in domains['domains'][i]['mxnames']:
                domains['domains'][i]['mxnames'][x].update({"ip": {}})

                for y in dr.resolve(x, 'A'):
                    z = y.to_text()
                    domains['domains'][i]['mxnames'][x]['ip'].update({z: {}})         
        



    def serverScan():

        for i in domains['domains']:
            for x in domains['domains'][i]['mxnames']:
                for ip in domains['domains'][i]['mxnames'][x]['ip']:
                    try:
                        print('='*30)
                        nmScan.scan(ip, str(port))
                            
                        print("IP: " + ip)
                        print("IP Status: ", nmScan[ip].state())
                        domains['domains'][i]['mxnames'][x]['ip'][ip].update({"Host Status": nmScan[ip].state()})
                        print("Port state: ", nmScan[ip]['tcp'][port]['state'] if nmScan[ip].get('tcp')  else "")
                        domains['domains'][i]['mxnames'][x]['ip'][ip].update({"Port State": nmScan[ip]['tcp'][port]['state']})

                        domains['domains'][i]['mxnames'][x]['ip'][ip].update({"Service Name": nmScan[ip]['tcp'][port]['name']})

                        lport = list(nmScan[ip]['tcp'].keys())
                        for ports in lport:
                            print('Port: %s\tService: %s' % (port, nmScan[ip]['tcp'][ports]['name']))


                        print('\b')
                    except KeyError as err: 
                        print(f"Unexpected {err=}, {type(err)=}")
        print(domains)



if args.spfrecords:
    domainEnumer.getTXT()
elif args.mxrecords:
    domainEnumer.getMX()
    domainEnumer.getIP()
    domainEnumer.serverScan()
else:
    print('Missing arguments')
if args.output:
    with open('result.json', 'w') as fp:
        json.dump(domains, fp)