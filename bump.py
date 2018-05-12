from scapy.all import *
import threading

def sendMessage(ip, message):
    ping = IP(dst="google.com", src=ip)/ICMP(id=2000)/message
    send(ping)

def receivePacket(packet):
    if packet[ICMP].type == 0:
        message = packet[Raw]
        print("\nMessage received : "+str(message))

def listenPackets():
    sniff(filter="icmp", prn=receivePacket)

thread = Thread(target = listenPackets)
thread.setDaemon(True)
thread.start()


import time
time.sleep(1)

dest = "192.168.0.29"

while True:
    message = raw_input("Entrez votre message : ")
    sendMessage(dest, message)
    continue;
