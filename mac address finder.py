import tkinter
from tkinter import *
#from  scapy_basics import *
from scapy.all import *
#from scapy_basics.py import *


def getmacaddr(ip):
    find_arp=Ether()/ARP()
    find_arp.dst="ff:ff:ff:ff:ff:ff"
    find_arp[ARP].pdst=ip
    response,ignored=srp(find_arp,timeout=1,retry=10)
    for x,y in response:
        return y[Ether].src

def printmac():
    #messagebox.showinfo("Action Event","you clicked this event")
    ip=e.get()
    mac=getmacaddr(ip)
    #messagebox.showinfo("Mac Address Found","mac")
    print(mac)

main=tkinter.Tk()
main.geometry("300x300")
main.title("Mac Address Finder")
label=Label(main,text="Enter IP Address")
label.pack()
e=Entry(main,bd=3)
e.pack()
b=tkinter.Button(main,text='get mac address',bd=3,command=printmac)
b.pack()
main.mainloop()
