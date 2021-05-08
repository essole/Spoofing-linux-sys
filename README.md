# Spoofing-linux-sys

**The required package for these scripts to work are:**
* Scapy for python 2.7 which you can clone on https://github.com/secdev/scapy.git
* Netfilterqueue for python 2.7 which you can clone on https://github.com/kti/python-netfilterqueue.git 
* The others packages are default install 


**Dnsspoofing script usage**
$ python Dns_spoof.py -s @Ipstl -d @IP_target -f dic.txt

* Ipstl here is the spoofed IP address here the DNS server IP address
* IP_target is the target machine ip address
* dic.txt is file that contain spoofed domain names and their ip address resolution
note that this file should be edited like: domain name : Ip address
* eventualy you can set a verbose or not

I would like to mentionned that I could write only the class that perform the DNSspoofing but I just wanted to write a script that can perform all the steps of a DNSspoofing

**ARPspoofing script usage**
$ python Arspspoofing.py -s @Ipstl -d @Ip_target

Note that these two scripts are written only for educational purpose
