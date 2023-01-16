import nmap
import sqlite3


# initialize the port scanner
nmScan = nmap.PortScanner()

# scan localhost for ports in range 21-443
nmScan.scan('192.168.1.1/24', '21-443')

# run a loop to print all the found result about the ports
for host in nmScan.all_hosts():
    print('#### Host : %s (%s)' % (host, nmScan[host].hostname()))
    print('State : %s' % nmScan[host].state())
    for proto in nmScan[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

        lport = nmScan[host][proto].keys()
        sorted(lport)
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))

# print result as CSV
print(nmScan.csv())

try:
    conn = sqlite3.connect('scanresults.db')
except Exception as e:
    raise nmap.PortScannerError('nmap.db can not be opened: %s' % e)
try:
    conn.execute('''CREATE TABLE nmap
                    (host text, hostname text, state text, protocol text, port text, name text, product text, version text, extrainfo text, reason text, conf text, cpe text)''')
except Exception as e:
    pass
for host in nmScan.all_hosts():
    hostname = nmScan[host].hostname()
    state = nmScan[host].state()
    for proto in nmScan[host].all_protocols():
        lport = nmScan[host][proto].keys()
        sorted(lport)
        for port in lport:
            name = nmScan[host][proto][port]['name']
            product = nmScan[host][proto][port]['product']
            version = nmScan[host][proto][port]['version']
            extrainfo = nmScan[host][proto][port]['extrainfo']
            reason = nmScan[host][proto][port]['reason']
            conf = nmScan[host][proto][port]['conf']
            cpe = nmScan[host][proto][port]['cpe']
            conn.execute("INSERT INTO nmap VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (host, hostname, state, proto, port, name, product, version, extrainfo, reason, conf, cpe))
conn.commit()
conn.close()
